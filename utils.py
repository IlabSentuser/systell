from datetime import timedelta

def time_parser(input):
    time = float(input[1:-1])
    unit = input[-1]
    if unit == 'd':
        return timedelta(days=time)
    elif unit == 'h':
        return timedelta(hours=time)
    elif unit == 'm':
        return timedelta(minutes=time)
    elif unit == 's':
        return timedelta(seconds=time)

        
def fprint(text):
    print('\033[38;2;{};{};{}m{} \033[38;2;255;255;255m'.format(100,100,100, text))