from project.crypto.token_utils import verify_token


class OrderAuthService:
    """
    订单认证流程管理
    """

    @staticmethod
    def handle_auth_request(request_data: dict) -> dict:
        """
        服务器处理认证请求
        :param request_data : 前端传来的数据包,含order_id,pid,timestamp,token
        """
        oid = request_data.get("order_id")
        pid = request_data.get("pid")
        ts = request_data.get("timestamp")
        token = request_data.get("token")

        if not all([oid, pid, ts, token]):
            return {
                "code": 400,
                "msg": "缺少订单认证参数",
                "can_access": False
            }

        try:
            is_valid = verify_token(oid, pid, ts, token)
        except Exception:
            is_valid = False

        if is_valid:
            return {
                "code": 200,
                "msg": "身份认证通过",
                "can_access": True,
                "room_id": f"chat_{oid}"
            }

        return {
            "code": 403,
            "msg": "身份验证失败或凭证已过期",
            "can_access": False
        }
