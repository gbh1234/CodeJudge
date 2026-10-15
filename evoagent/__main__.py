"""命令行启动入口。

``python -m evoagent`` 只负责把控制权交给 HTTP 服务层；依赖装配、队列启动
和业务逻辑由 :mod:`evoagent.api` 与 :mod:`evoagent.service` 完成。
"""

from .api import run


if __name__ == "__main__":
    run()
