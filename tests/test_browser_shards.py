import unittest

from browser_shards import select_shard


class BrowserShardTests(unittest.TestCase):
    def test_runs_every_test_once_across_balanced_shards(self):
        names = [f"test_{index}" for index in range(41)]
        for total in [2, 3, 4]:
            with self.subTest(total=total):
                shards = [select_shard(names, f"{index}/{total}") for index in range(1, total + 1)]
                selected = [name for shard in shards for name in shard]
                self.assertCountEqual(selected, names)
                self.assertLessEqual(max(map(len, shards)) - min(map(len, shards)), 1)

    def test_runs_the_complete_suite_in_one_shard(self):
        names = ["test_first", "test_second", "test_third"]
        self.assertEqual(select_shard(names, "1/1"), names)

    def test_reports_invalid_or_empty_shards(self):
        for specification in ["1", "1/2/3", "one/two", "0/2", "3/2", "1/0", "-1/2", "1/4"]:
            with self.subTest(specification=specification):
                with self.assertRaises(ValueError):
                    select_shard(["test_first", "test_second", "test_third"], specification)


if __name__ == "__main__":
    unittest.main()
