"""LazyProxy 单元测试 —— 线程安全的惰性代理。

覆盖：
- 惰性实例化（工厂仅在首次访问时调用一次）
- 线程安全（双重检查锁定，并发访问）
- 属性/方法委托（__getattr__）
- 容器协议（dunder 方法：__getitem__/__setitem__/__iter__/__len__ 等）
- 异常传播
"""

from __future__ import annotations

import threading
import unittest

from openclaw_guard.utils import LazyProxy


class LazyProxyBasicTests(unittest.TestCase):
    """惰性实例化与属性委托基本测试。"""

    def test_factory_not_called_until_first_access(self) -> None:
        called = []

        def factory():
            called.append(True)
            return type("Obj", (), {"value": 42})()

        proxy = LazyProxy(factory)
        self.assertEqual(len(called), 0, "factory should not be called before first access")
        _ = proxy.value
        self.assertEqual(len(called), 1, "factory should be called on first access")

    def test_factory_called_exactly_once(self) -> None:
        call_count = [0]

        def factory():
            call_count[0] += 1
            return type("Obj", (), {"a": 1, "b": 2})()

        proxy = LazyProxy(factory)
        _ = proxy.a
        _ = proxy.b
        _ = proxy.a
        self.assertEqual(call_count[0], 1, "factory should be called exactly once")

    def test_attribute_access_delegates_to_instance(self) -> None:
        proxy = LazyProxy(lambda: type("Obj", (), {"name": "test", "value": 99})())
        self.assertEqual(proxy.name, "test")
        self.assertEqual(proxy.value, 99)

    def test_method_call_delegates_to_instance(self) -> None:
        class Obj:
            def greet(self, name: str) -> str:
                return f"Hello, {name}"

        proxy = LazyProxy(lambda: Obj())
        self.assertEqual(proxy.greet("World"), "Hello, World")


class LazyProxyThreadSafetyTests(unittest.TestCase):
    """双重检查锁定 —— 多线程并发首次访问时只调用一次工厂。"""

    def test_concurrent_access_creates_exactly_one_instance(self) -> None:
        call_count = [0]
        lock = threading.Lock()

        def factory():
            with lock:
                call_count[0] += 1
            return type("Obj", (), {"value": 42})()

        proxy = LazyProxy(factory)
        results: list[object] = []
        barrier = threading.Barrier(8)
        errors: list[Exception] = []

        def worker() -> None:
            try:
                barrier.wait()
                results.append(proxy.value)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"unexpected errors: {errors}")
        self.assertEqual(call_count[0], 1, "factory should be called exactly once under concurrency")
        self.assertEqual(len(results), 8)
        for r in results:
            self.assertEqual(r, 42)


class LazyProxyContainerProtocolTests(unittest.TestCase):
    """dict-like 实例的 dunder 方法透传。"""

    def setUp(self) -> None:
        self.proxy = LazyProxy(lambda: {"a": 1, "b": 2, "c": 3})

    def test_getitem(self) -> None:
        self.assertEqual(self.proxy["a"], 1)
        self.assertEqual(self.proxy["b"], 2)

    def test_setitem(self) -> None:
        self.proxy["d"] = 4
        self.assertEqual(self.proxy["d"], 4)

    def test_delitem(self) -> None:
        del self.proxy["c"]
        self.assertNotIn("c", self.proxy)

    def test_contains(self) -> None:
        self.assertIn("a", self.proxy)
        self.assertNotIn("z", self.proxy)

    def test_iter(self) -> None:
        keys = list(iter(self.proxy))
        self.assertEqual(sorted(keys), ["a", "b", "c"])

    def test_len(self) -> None:
        self.assertEqual(len(self.proxy), 3)

    def test_bool(self) -> None:
        self.assertTrue(bool(self.proxy))
        empty = LazyProxy(lambda: {})
        self.assertFalse(bool(empty))

    def test_repr(self) -> None:
        r = repr(self.proxy)
        self.assertIn("'a'", r)
        self.assertIn("1", r)

    def test_dict_conversion(self) -> None:
        """dict(LazyProxy(dict_factory)) 应等同于 dict。"""
        d = dict(self.proxy)
        self.assertEqual(d, {"a": 1, "b": 2, "c": 3})


class LazyProxyExceptionTests(unittest.TestCase):
    """工厂异常应传播给调用方。"""

    def test_factory_exception_propagates(self) -> None:
        proxy = LazyProxy(lambda: (_ for _ in ()).throw(RuntimeError("init failed")))

        with self.assertRaises(RuntimeError) as ctx:
            _ = proxy.anything
        self.assertIn("init failed", str(ctx.exception))

    def test_second_access_after_failed_first_retries(self) -> None:
        """首次工厂调用失败后，第二次访问应重试工厂（_instance 仍为 None）。"""
        attempts = [0]

        def factory():
            attempts[0] += 1
            if attempts[0] < 2:
                raise RuntimeError("not ready")
            return type("Obj", (), {"ok": True})()

        proxy = LazyProxy(factory)
        with self.assertRaises(RuntimeError):
            _ = proxy.ok
        # 第二次访问：重试工厂
        self.assertTrue(proxy.ok)
        self.assertEqual(attempts[0], 2)


class LazyProxyRegressionTests(unittest.TestCase):
    """Phase 3 引入的特定回归保护。"""

    def test_proxy_on_none_value(self) -> None:
        """LazyProxy 不应吞掉 None 实例（__bool__ 正确处理空容器）。"""
        proxy = LazyProxy(lambda: None)
        self.assertFalse(bool(proxy))

    def test_list_proxy(self) -> None:
        """LazyProxy 也能代理 list。"""
        proxy = LazyProxy(lambda: [10, 20, 30])
        self.assertEqual(len(proxy), 3)
        self.assertEqual(proxy[0], 10)
        proxy.append(40)
        self.assertEqual(len(proxy), 4)


if __name__ == "__main__":
    unittest.main()
