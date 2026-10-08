"""有界识别内联Python的潜在能力；不执行代码，不证明实际副作用或只读。"""
from __future__ import annotations

import ast


def inline_python_effects(argv: list[str]) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """支持明确的-c参数及常见导入别名，未知语法保留unknown。"""
    args = argv[1:]
    flags = {'-I', '-B', '-E', '-s', '-S', '-u', '-O', '-OO'}
    while args and args[0] in flags:
        args = args[1:]
    code = args[1] if len(args) >= 2 and args[0] == '-c' else (
        args[0][2:] if args and args[0].startswith('-c') and len(args[0]) > 2 else None)
    if code is None:
        # 文件/-m调用沿用既有未知/变更诊断；没有内联源码可增加AST证据。
        return ('unknown',), (), ()
    if len(code) > 8192:
        return ('unknown',), (), ('inline_python_budget',)
    try:
        nodes = []
        for node in ast.walk(ast.parse(code)):
            nodes.append(node)
            if len(nodes) > 512:
                return ('unknown',), (), ('inline_python_budget',)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return ('unknown',), (), ('inline_python_parse_error',)
    aliases, paths = {}, set()
    effects = {'unknown'}  # 静态命中不把整个解释器变成可自动放行的只读工具。
    for node in nodes:
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for item in node.names:
                aliases[item.asname or item.name] = node.module + '.' + item.name

    def name(node):
        """解析语法中的导入名称，不读取对象或执行属性访问。"""
        if isinstance(node, ast.Name):
            if node.id in path_objects:
                return 'pathlib.Path()'
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = name(node.value)
            return base + '.' + node.attr if base else ''
        if isinstance(node, ast.Call) and name(node.func) == 'pathlib.Path':
            return 'pathlib.Path()'
        return ''

    # 只扩展明确Path构造及其简单变量别名，不执行数据流或动态属性。
    # 集合单调增长：重绑定/分支可导致保守误报，unknown始终保留。
    path_objects: set[str] = set()
    for _ in range(16):
        previous = len(path_objects)
        for node in nodes:
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign):
                targets, value = [node.target], node.value
            else:
                continue
            if value is not None and name(value) == 'pathlib.Path()':
                path_objects.update(target.id for target in targets if isinstance(target, ast.Name))
        if len(path_objects) == previous:
            break

    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        called = name(node.func)
        if called in {'os.remove', 'os.unlink', 'os.rmdir', 'os.removedirs', 'shutil.rmtree',
                      'pathlib.Path().unlink', 'pathlib.Path().rmdir'}:
            effects.add('delete')
        if called in {'os.rename', 'os.replace', 'shutil.move', 'pathlib.Path().rename', 'pathlib.Path().replace'}:
            effects.update(('read', 'write', 'delete', 'transform'))
        if called in {'shutil.copy', 'shutil.copy2', 'shutil.copyfile'}:
            effects.update(('read', 'write', 'transform'))
        if called in {'pathlib.Path().write_text', 'pathlib.Path().write_bytes', 'pathlib.Path().touch',
                      'pathlib.Path().mkdir', 'os.mkdir', 'os.makedirs'}:
            effects.add('write')
        if called in {'pathlib.Path().read_text', 'pathlib.Path().read_bytes'}:
            effects.add('read')
        if called in {'open', 'io.open', 'builtins.open', 'pathlib.Path().open'}:
            mode_index = 0 if called == 'pathlib.Path().open' else 1
            mode = next((k.value for k in node.keywords if k.arg == 'mode'),
                        node.args[mode_index] if len(node.args) > mode_index else ast.Constant('r'))
            if not isinstance(mode, ast.Constant) or not isinstance(mode.value, str):
                effects.update(('read', 'write'))
            elif '+' in mode.value:
                effects.update(('read', 'write'))
            else:
                effects.add('write' if any(c in mode.value for c in 'wax') else 'read')
        if called in {'requests.get', 'requests.post', 'requests.put', 'requests.delete', 'requests.request',
                      'requests.patch', 'requests.head', 'requests.options',
                      'urllib.request.urlopen', 'urllib.request.urlretrieve', 'httpx.get', 'httpx.post',
                      'httpx.put', 'httpx.patch', 'httpx.delete', 'httpx.head', 'httpx.options', 'httpx.request',
                      'socket.create_connection'}:
            effects.add('egress')
        if called in {'exec', 'eval', 'compile', '__import__', 'os.system', 'os.popen',
                      'subprocess.run', 'subprocess.call', 'subprocess.Popen', 'subprocess.check_call',
                      'subprocess.check_output'}:
            effects.add('execute')
        if called == 'pathlib.Path' or called in {'open', 'os.remove', 'os.unlink', 'os.rmdir', 'shutil.rmtree'}:
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                paths.add(node.args[0].value)
    return tuple(sorted(effects)), tuple(sorted(paths)[:16]), ('inline_python_static_capabilities',)
