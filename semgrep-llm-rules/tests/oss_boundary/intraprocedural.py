def source():
    return "tainted"


def sink(x):
    print(x)


def one_function_flow():
    # Taint source and sink are in the same function.
    val = source()
    sink(val)
