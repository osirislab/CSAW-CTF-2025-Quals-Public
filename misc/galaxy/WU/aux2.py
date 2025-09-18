# atoms
ONE = "([]<[[]])"
ZERO = "([]>[])"

payload_memo = {}
tester = "csawctf{g@l@xy_0bserv3r$}"
def num(n):
    if n == 0:
        return ZERO
    return "+".join([ONE] * n)

def payload_for(n):
    if n in payload_memo:
        return payload_memo[n]

    if n <= 7:
        expr = f"({num(n)})"
        payload_memo[n] = expr
        return expr

    candidates = []

    for base in range(2, 6):
        for exp in range(2, 6):
            power = base ** exp
            if power > n:
                continue
            remainder = n - power
            expr = f"({num(base)})**({num(exp)})"
            if remainder > 0:
                expr += f"+({payload_for(remainder)})"
            candidates.append(expr)

    candidates.append(num(n))

    best_expr = min(candidates, key=len)
    payload_memo[n] = best_expr
    return best_expr

payloads = [f"~({payload_for(i)})" for i in range(1, 26)]

maxima_payload = -float('inf')
# print results
for i, p in enumerate(payloads, 1):
    try:
        # print(eval(f'tester[{p}]'))
        # print(p)
        length_pay = len(p)
        if length_pay>maxima_payload:
            maxima_payload = length_pay
        # print(p)
        print(f"{i}: {p}")
    except:
        break

print(maxima_payload)