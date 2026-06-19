from project.crypto.sm_utils import sm3_strhash


def generate_hash(data: str) -> str:
    """
    基础 Hash 生成函数，用于计算消息 Hash、构建 Merkle Tree
    使用国密 SM3 替代 SHA-256
    :param data: 需要计算哈希值的原始字符串
    :return: 64位十六进制字符串
    """
    return sm3_strhash(data)


def hash_message(order_id: str, sender_pid: str, role: str, content: str, timestamp: str) -> str:
    """
    计算单条消息的消息哈希
    :param order_id: 订单号
    :param sender_pid: 发送方匿名身份标识
    :param role: 发送方角色（user / rider / system）
    :param content: 聊天明文内容
    :param timestamp: 消息时间戳
    :return: 消息哈希值
    """
    # 用分隔符防止字段拼接歧义
    message_str = "|".join([order_id, sender_pid, role, content, timestamp])
    return generate_hash(message_str)


class MerkleTree:
    """
    基于迭代列表的轻量级 Merkle Tree
    """
    def __init__(self, leaves: list[str]):
        # leaves 为包含多条消息 msg_hash 的列表
        self.leaves = [leaf.lower() for leaf in leaves if leaf]

    def get_root(self) -> str:
        """
        计算并返回 Merkle Root
        """
        # 如果没有日志，返回固定值的 Hash
        if not self.leaves:
            return generate_hash("EMPTY")

        current_level = self.leaves[:]

        # 当前层级节点数大于 1 时，继续向上构建
        while len(current_level) > 1:
            next_level = []

            # 两两配对
            for i in range(0, len(current_level), 2):
                left = current_level[i]

                # 奇数个节点时，复制最后一个节点
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = left

                combined = left + right
                next_level.append(generate_hash(combined))

            current_level = next_level

        return current_level[0]


def build_merkle_root(hashes: list[str]) -> str:
    """
    直接根据消息哈希列表生成 Merkle Root，便于后端调用
    """
    tree = MerkleTree(hashes)
    return tree.get_root()


if __name__ == "__main__":
    print("=" * 30, "测试 Merkle Tree", "=" * 30)

    h1 = generate_hash("msg1")
    h2 = generate_hash("msg2")
    h3 = generate_hash("msg3")

    leaves_list = [h1, h2, h3]
    root = build_merkle_root(leaves_list)

    print(f"叶子节点数: {len(leaves_list)}")
    print(f"生成的 Merkle Root: {root}")

    print("=" * 30, "测试篡改", "=" * 30)
    h4_fake = generate_hash("msg4")
    changed_leaves = [h1, h2, h3, h4_fake]
    fake_root = build_merkle_root(changed_leaves)

    print(f"叶子节点数: {len(changed_leaves)}")
    print(f"篡改后的 Merkle Root: {fake_root}")