def select_shard(test_names, specification):
    try:
        index, total = (int(part) for part in specification.split("/"))
    except ValueError as error:
        raise ValueError("Browser shard must have the form INDEX/TOTAL.") from error
    if not 1 <= index <= total <= len(test_names):
        raise ValueError("Each browser shard must select at least one test with 1 <= INDEX <= TOTAL.")
    return test_names[index - 1::total]
