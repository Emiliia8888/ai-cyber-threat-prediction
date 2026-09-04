training_data = [
    # normal activity
    ([0, 0, 0], "normal"),
    ([1, 0, 0], "normal"),
    ([0, 0, 1], "normal"),
    ([1, 0, 1], "normal"),

    # low threat: authentication problems
    ([0, 1, 0], "low"),
    ([0, 2, 0], "low"),
    ([0, 3, 0], "low"),
    ([0, 2, 1], "low"),

    # medium threat: scanning + failed login
    ([1, 1, 0], "medium"),
    ([2, 1, 0], "medium"),
    ([3, 1, 0], "medium"),
    ([2, 2, 0], "medium"),

    # high threat: scan + failed login + successful login
    ([1, 1, 1], "high"),
    ([2, 1, 1], "high"),
    ([2, 2, 1], "high"),
    ([3, 2, 1], "high"),
]

