def source():
    return "tainted"


def sink(x):
    print(x)


def function_a():
    # Taint originates here...
    val = source()
    function_b(val)


def function_b(val):
    # ...and reaches the sink only in a different function.
    sink(val)
