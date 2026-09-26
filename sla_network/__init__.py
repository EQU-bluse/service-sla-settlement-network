"""Machine-service SLA settlement network."""

import sys

# 公开入口接受任意长度的非布尔正整数端点（超出存储范围按不存在处理），
# 不得因解释器默认的整数字符串转换位数上限（PEP 682）将合法 JSON 判为非法或断连；
# 同样保证超大整数的序列化（幂等记录等）可用。
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

__version__ = "0.1.0"
