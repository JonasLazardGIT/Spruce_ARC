from math import *
import sys

if len(sys.argv) < 7:
    print("Usage: sage prf/sweep_rounds.sage <field_bits> <modulus_hex> <alpha> <security> <t_min> <t_max> [lentag]")
    sys.exit(1)

FIELD_BITS = int(sys.argv[1])
PRIME_NUMBER = int(sys.argv[2], 16)
ALPHA = int(sys.argv[3])
SECURITY_LEVEL = int(sys.argv[4])
T_MIN = int(sys.argv[5])
T_MAX = int(sys.argv[6])
LENTAG = None
if len(sys.argv) >= 8:
    LENTAG = int(sys.argv[7])

def sat_inequiv_alpha(p, t, R_F, R_P, alpha, M):
    if alpha <= 0:
        return False
    R_F_1 = 6 if M <= ((floor(log(p, 2) - ((alpha-1)/2.0))) * (t + 1)) else 10
    R_F_2 = 1 + ceil(log(2, alpha) * min(M, FIELD_BITS)) + ceil(log(t, alpha)) - R_P
    R_F_3 = (log(2, alpha) * min(M, log(p, 2))) - R_P
    R_F_4 = t - 1 + log(2, alpha) * min(M / float(t + 1), log(p, 2) / float(2)) - R_P
    R_F_5 = (t - 2 + (M / float(2 * log(alpha, 2))) - R_P) / float(t - 1)
    R_F_max = max(ceil(R_F_1), ceil(R_F_2), ceil(R_F_3), ceil(R_F_4), ceil(R_F_5))
    r_temp = floor(t / 3.0)
    over = (R_F - 1) * t + R_P + r_temp + r_temp * (R_F / 2.0) + R_P + alpha
    under = r_temp * (R_F / 2.0) + R_P + alpha
    binom_log = log(binomial(over, under), 2)
    if binom_log == inf:
        binom_log = M + 1
    cost_gb4 = ceil(2 * binom_log)
    return ((R_F >= R_F_max) and (cost_gb4 >= M))

def get_sbox_cost(R_F, R_P, N, t):
    return int(t * R_F + R_P)

def find_FD_round_numbers(p, t, alpha, M, cost_function, security_margin):
    N = int(FIELD_BITS * t)
    R_P = 0
    R_F = 0
    min_cost = float("inf")
    max_cost_rf = 0
    for R_P_t in range(1, 500):
        for R_F_t in range(4, 100):
            if R_F_t % 2 != 0:
                continue
            if not sat_inequiv_alpha(p, t, R_F_t, R_P_t, alpha, M):
                continue
            if security_margin:
                R_F_t += 2
                R_P_t = int(ceil(float(R_P_t) * 1.075))
            cost = cost_function(R_F_t, R_P_t, N, t)
            if (cost < min_cost) or ((cost == min_cost) and (R_F_t < max_cost_rf)):
                R_P = ceil(R_P_t)
                R_F = ceil(R_F_t)
                min_cost = cost
                max_cost_rf = R_F
    return (int(R_F), int(R_P))

def calc_final_numbers_fixed(p, t, alpha, M, security_margin):
    N = int(FIELD_BITS * t)
    cost_function = get_sbox_cost
    (R_F, R_P) = find_FD_round_numbers(p, t, alpha, M, cost_function, security_margin)
    min_sbox_cost = cost_function(R_F, R_P, N, t)
    return (int(R_F), int(R_P), int(min_sbox_cost))

def perm_bits_estimate(t):
    return t * log(PRIME_NUMBER, 2) / 3.0

print("t, RF, RP, sboxes, perm_bits, trunc_ok")
for t in range(T_MIN, T_MAX + 1):
    (RF, RP, sboxes) = calc_final_numbers_fixed(PRIME_NUMBER, t, ALPHA, SECURITY_LEVEL, True)
    trunc_ok = ""
    if LENTAG is not None:
        trunc_bound = SECURITY_LEVEL / log(PRIME_NUMBER, 2)
        trunc_ok = "ok" if (t - LENTAG) > trunc_bound else "fail"
    print("%d, %d, %d, %d, %.2f, %s" % (t, RF, RP, sboxes, perm_bits_estimate(t), trunc_ok))