from secure_credentials.src.api.auth import LoginThrottle, SessionStore


class FakeClock:
    def __init__(self) -> None:
        self.now: float = 1000.0

    def __call__(self) -> float:
        return self.now


def test_throttle_free_attempts_then_backoff_then_reset() -> None:
    clock = FakeClock()
    t = LoginThrottle(free_attempts=2, clock=clock)
    t.record_failure("a")
    t.record_failure("a")
    assert t.retry_after("a") == 0
    t.record_failure("a")
    assert t.retry_after("a") == 1
    clock.now += 2
    assert t.retry_after("a") == 0
    t.record_failure("a")
    assert t.retry_after("a") == 2
    t.record_success("a")
    assert t.retry_after("a") == 0
    assert t.retry_after("other") == 0


def test_throttle_delay_is_capped_and_memory_bounded() -> None:
    clock = FakeClock()
    t = LoginThrottle(free_attempts=0, max_delay=8.0, max_keys=3, clock=clock)
    for _ in range(10):
        t.record_failure("a")
    assert t.retry_after("a") == 8
    for i in range(5):
        clock.now += 1
        t.record_failure(f"k{i}")
    assert len(t._state) <= 3


def test_session_idle_expiry_and_touch() -> None:
    clock = FakeClock()
    s = SessionStore(idle_seconds=60, clock=clock)
    token = s.create()
    assert s.seconds_left(token) == 60
    clock.now += 50
    assert s.touch(token)
    clock.now += 50
    assert s.touch(token)
    clock.now += 61
    assert not s.touch(token)
    assert s.purge() == 0


def test_session_seconds_left_does_not_refresh_and_unknown_token() -> None:
    clock = FakeClock()
    s = SessionStore(idle_seconds=60, clock=clock)
    token = s.create()
    clock.now += 30
    assert s.seconds_left(token) == 30
    assert s.seconds_left(token) == 30
    assert s.seconds_left("nope") is None
    assert not s.touch(None)
    s.revoke_all()
    assert not s.touch(token)
