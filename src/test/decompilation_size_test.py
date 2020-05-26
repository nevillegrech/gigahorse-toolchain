from collections import namedtuple
import unittest
from typing import Tuple, List

from src.test.utils.souffle_utils import Decompilation
from src.test.common import rubus_bytecode_path

TestCase = namedtuple('TestCase', ['bytecode_path', 'blocks', 'jump_to_many', 'poly_target', 'poly_target_same_ctx'])


class DecompilationSizeTest(unittest.TestCase):
    test_cases = (
        TestCase(rubus_bytecode_path, 431, 1, 0, 0),
    )

    relation_names = (
        'Analytics_Blocks.csv',
        'Analytics_JumpToMany.csv',
        'Analytics_PolymorphicTarget.csv',
        'Analytics_PolymorphicTargetSameCtx.csv'
    )

    def test_relation_size_approx(self):
        for test_case in self.test_cases:
            with self.subTest(test_case=test_case):
                decompilation = Decompilation(test_case.bytecode_path)

                decompilation.run()

                sizes = self.extract_relation_size(decompilation, self.relation_names)

                self.assertTrue(all(self.within_margin(0.1, x, y) for x, y in zip(sizes, test_case[1:])))

    @staticmethod
    def within_margin(margin: float, actual, expected):
        return (1 - margin) * expected <= actual <= (1 + margin) * expected

    @staticmethod
    def extract_relation_size(decompilation: Decompilation, relations: Tuple[str, ...]) -> Tuple[int, ...]:
        sizes: List[int] = []
        for relation in relations:
            with open(f'{decompilation.out_dir}/{relation}') as f:
                sizes.append(sum(1 for _ in f))

        return tuple(sizes)


if __name__ == '__main__':
    unittest.main()
