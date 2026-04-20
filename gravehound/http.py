import httpx
import asyncio
import time
from gravehound.tor import get_proxy

class _RetryMixin:
    def _execute_with_retries(self, func, method, url, *args, **kwargs):
        retries = kwargs.pop('retries', 3)
        for i in range(retries):
            try:
                return func(method, url, *args, **kwargs)
            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError) as e:
                if i == retries - 1:
                    raise
                time.sleep(1.5 * (i + 1))

class _AsyncRetryMixin:
    async def _execute_with_retries_async(self, func, method, url, *args, **kwargs):
        retries = kwargs.pop('retries', 3)
        for i in range(retries):
            try:
                return await func(method, url, *args, **kwargs)
            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError) as e:
                if i == retries - 1:
                    raise
                await asyncio.sleep(1.5 * (i + 1))

class Client(httpx.Client, _RetryMixin):
    def __init__(self, *args, **kwargs):
        if 'proxy' not in kwargs:
            kwargs['proxy'] = get_proxy()
        super().__init__(*args, **kwargs)

    def request(self, method, url, *args, **kwargs):
        return self._execute_with_retries(super().request, method, url, *args, **kwargs)

class AsyncClient(httpx.AsyncClient, _AsyncRetryMixin):
    def __init__(self, *args, **kwargs):
        if 'proxy' not in kwargs:
            kwargs['proxy'] = get_proxy()
        super().__init__(*args, **kwargs)

    async def request(self, method, url, *args, **kwargs):
        return await self._execute_with_retries_async(super().request, method, url, *args, **kwargs)
