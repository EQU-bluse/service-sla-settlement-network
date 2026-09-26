"""Machine-service SLA settlement network."""

import sys

# README 的三类审计序号接受任意长度非布尔正整数（超出存储范围按不存在处理），
# 服务端在受控 JSON 解析器中逐位转换这些字段；全局放开解释器整数字符串转换
# 位数上限（PEP 682），其他 JSON 整数的转换保护由 server 的解析器单独保留：
# 非审计序号字段的超长整数一律按非法请求处理，不断连。
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

__version__ = "0.1.0"
