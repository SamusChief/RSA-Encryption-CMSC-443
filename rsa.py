"""
    Author: Tristan Adams
    Email: tristana@umbc.edu OR tristangadams@gmail.com
    ID: GM47494
    Date: 11/1/2016
    Python Version: 3.5. Some parts of this program may not function properly if used with older versions of Python,
        such as Python 2.2

    Description: This file is designed to demonstrate RSA Encryption algorithms using plaintext.
    Keep in mind in a real world situation, the RSA code would not be used to encrypt plaintext, but would be used on
        binary data instead.

    Sources: Algorithms used are adapted from pseudocode present in Cryptography: Theory and Practice by D.R. Stinson
             3rd edition
"""
from random import getrandbits, randint
from statistics import mean, median
from time import clock


def decode(n, b=26):
    """
    Converts a number n in base 10 to base b, in a list. For our purposes, we want to use this to decipher a string from
    an integer, so b will default to 26
    Example: 2398 -> DOG (2398_10 = [3,14,6]_26, corresponding to letters D, O, and G
    :param n: The number to convert to a new base, in decimal
    :param b: The base to convert to
    :return: A decoded string
    """
    if n == 0:
        return [0]
    chars = []
    while n:
        chars.append(chr(int(n % b) + 97))
        n //= b
    # Be sure to reverse the list for returning properly
    return ''.join(chars[::-1])


def encode(message, b=26):
    """
    Encode a string of characters as a decimal representation of a base 26 number
        a=0, b=1, c=2, etc...
    Example:
        DOG -> 2398 (3 * 26^2 + 14 * 26 + 6)
    :param message: A string to be encoded
    :param b: the base to convert to, defaults at 26 (alphabet)
    :return: the decimal representation of the base 26 number
    """
    m_list = list(message.lower())
    for i in range(0, len(m_list)):
        m_list[i] = ord(m_list[i]) - 97
    # convert this list of base 26 numbers into one number, which can be encrypted
    m_num = 0
    m_len = len(m_list) - 1
    for i in m_list:
        m_num += (i * (b ** m_len))
        m_len -= 1
    return m_num


def extended_gcd(a0, b0):
    """
    Computes greatest common divisor for a given a and b
    :param a0: the initial a value
    :param b0: the initial b value
    """
    last_remainder, remainder = abs(a0), abs(b0)
    x, last_x, y, last_y = 0, 1, 1, 0
    while remainder:
        last_remainder, (quotient, remainder) = remainder, divmod(last_remainder, remainder)
        x, last_x = last_x - quotient * x, x
        y, last_y = last_y - quotient * y, y
    return last_remainder, last_x * (-1 if a0 < 0 else 1), last_y * (-1 if b0 < 0 else 1)


def mod_inv(a, m):
    """
    Gets the modular inverse, i, such that (a * i) mod m = 1
    :param a:
    :param m:
    :return: the modular inverse as stated above
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m


def mod_exp_55(message, exponent, modulo):
    """
    Calculates modular exponentiation based on the Algorithm 5.5 in Cryptography: Theory and Practice by D.R. Stinson
    :param message: the base
    :param exponent:
    :param modulo:
    :return: the calculated number
    """
    if exponent <= 0:
        return 1
    b = message
    ex = exponent
    res = 1
    while ex > 0:
        if not ex & 1:
            b = (b * b) % modulo
            ex //= 2
        else:
            res = (b * res) % modulo
            ex -= 1
    return res


def miller_rabin(n, t=10):
    """
    Tests a number, n, for primality according to the Miller-Rabin algorithm (5.7 in Stinson Cryptography textbook)
    :param n: the number to test for primality, 512 bits in length and odd
    :param t: the number of times to run our test. Defaults to 10
    :return: True if n is possibly prime, False if definitely not prime
    """

    def check(a_check, k_check, num_sub, num):
        """
        A sub-function to check our number for primality
        """
        x = pow(a_check, num_sub, num)
        if x == 1:
            return True
        for j in range(k_check - 1):
            if x == num - 1:
                return True
            x = pow(x, 2, num)
        return x == num - 1

    k = 0
    n_sub = n - 1
    # acquire our k for the m-r algorithm; divide by two (or bit shift) repeatedly until we cannot anymore
    while n_sub % 2 == 0:
        n_sub >>= 1
        k += 1
    # run our test t times, 10 by default
    for i in range(t):
        a = randint(2, n - 1)
        if not check(a, k, n_sub, n):
            return False

    return True


def get_prime():
    """
    Generates a random 512 bit integer and tests it for primality
    :return: False if the number is not prime, or the number which may be prime
    """
    n = getrandbits(512)
    if not n & 1:
        n += 1
    if not miller_rabin(n):
        return False
    return n


"""
    When conducted 200 times, here are stats about the key_gen() function's speed
    - Average time: 0.61
    - Maximum time: 3.46
    - Median time: 0.44
    - Minimum time: 0.05

    For reference: Here are my computer's specifications:
        Processor: 1.7 GHz 2.4 GHz
        RAM: 8 GB (~7.88 usable)
        64 bit processor
        Python version: 3.5
"""


def key_gen():
    """
    Generates a public key and a private key for RSA encryption
    :return: a tuple containing our public and private keys, both consisting of pairs
    """

    """
    I use 65537 for b for a few reasons:
    - It is coprime with our chosen n since it is also prime
        - It is a fermat prime, meaning it is of the form 2^2^4 + 1
            - This means in binary it is both prime and has only two 1's in it, so it is faster to use on
              a computer using bit shifting (65537 in binary is 100000000000000001)
    - It is a known large prime, and using it is MUCH faster than calculating
      a co-prime number manually every time
    In a situation where speed is not as much of a concern, generating a random b may prove to be a more secure
    option
    """
    b = 65537

    # generate our p and q, testing them for primality using the miller-rabin test, done 10 times in our case
    # the number of trials could be reduced to potentially increase speed, but at the cost of accuracy, or increased to
    # potentially gain accuracy
    p = get_prime()
    q = get_prime()
    while not p:
        p = get_prime()
    while not q:
        q = get_prime()
    n = p * q
    # Our public key is complete! assign to a variable to be returned later
    # If memory is a concern, the function could jsut be changed to return (n, b), (p, q, a) with the same results
    public_key = (n, b)

    """
        Normally, Euler's Phi formula says to do (p^n - p^(n-1)) * (q^n - q^(n-1)) multiplied to whatever other factors
        we have for our number, n.
        Since our p and q are prime, phi(n) in this case is (p - 1) * (q - 1)
    """
    phi = (p - 1) * (q - 1)
    # Our a will be the multiplicative inverse of our phi and b, completing our private key.
    a = mod_inv(b, phi)
    # Assemble our private key for returning
    private_key = (p, q, a)
    # We return our key pair. See the top of this file for some statistics on this function
    return public_key, private_key


def rsa(n, e, message):
    """
    Encrypts or decrypts a given integer representation of a string, based on e
    :param n:
    :param e:
    :param message:
    :return:
    """
    # eK(x) = (x ** b) % n
    return mod_exp_55(message, e, n)


def print_menu():
    """
    Prints the menu each loop, for user convenience
    """
    print("Welcome to the RSA Encryption demo by Tristan Adams. Please enter what you would like to do:")
    print("0 - Test key_gen function and gather statistics")
    print("1 - Generate a public/private key pair")
    print("2 - Encrypt a plaintext using a public key")
    print("3 - Decrypt a plaintext using a private key")
    print("4 - Exit program")
    print("-------------------------------IMPORTANT NOTE-------------------------------")
    print("When encrypting strings, this program will ignore non-alphabetical characters.\n")


def main():
    """
    Allows user to generate keys, run tests, decrypt, and encrypt to different specified files
    """
    print("This program was made to model RSA Encryption protocol as defined in Cryptography: Theory and Practice")
    print("\t\t(3rd edition) by D.R. Stinson, and with lecture notes created by Michael Novey.\n")

    # Loop forever unless '4 - Exit program' is selected
    while True:
        print_menu()
        choice = int(input("Please enter your choice here: "))
        # Gather stats and test key_gen function
        if choice == 0:
            n = int(input("Enter the number of times to test: "))
            times = []
            for i in range(n):
                start_time = clock()
                key_gen()
                end_time = clock() - start_time
                print("Time to generate: ", end_time)
                times.append(end_time)
            print("Average Time: ", mean(times))
            print("Maximum Time: ", max(times))
            print("Median Time: ", median(times))
            print("Minimum Time: ", min(times))

        # Generate one key pair, and print it to either the screen or to a file
        elif choice == 1:
            print("Generating a key pair now...")
            start_time = clock()
            key_pair = key_gen()
            print("Finished generating this key pair in", clock() - start_time, "seconds.")
            # Print out the generated key pair, either to a specified file or to the screen
            print_to_file = input("Would you like to output to a file? Enter y for yes, or any other string for no: ")
            if print_to_file == 'y':
                filename = input("Please input the filename for the public key: ")
                f_out = open(filename, 'w')
                # split the key pair into its parts: its a pair of tuples, the first containing n and b (public)
                # , the second containing p, q, and a (private key)
                public_n = str(key_pair[0][0])
                public_b = str(key_pair[0][1])
                private_p = str(key_pair[1][0])
                private_q = str(key_pair[1][1])
                private_a = str(key_pair[1][2])
                # print the compiled string into the user designated file, and close the file
                f_out.write(public_n + '\n' + public_b)
                f_out.close()
                # print the private key to its own file
                private_filename = input("Please input the filename for the private key: ")
                private_key_file = open(private_filename, 'w')
                private_key_file.write(private_p + "\n" + private_q + "\n" + private_a)
                private_key_file.close()
            else:
                print("N:", key_pair[0][0])
                print("B:", key_pair[0][1])
                print("P:", key_pair[1][0])
                print("Q:", key_pair[1][1])
                print("A:", key_pair[1][2])
        # Encrypt a string using a key input by the user (or taken in from a file)
        elif choice == 2:
            # Step 1: get the key from a file designated by the user (public key is the first line, private is second)
            filename = input("Please enter the filename where the public key is contained: ")
            key_file = open(filename, 'r')
            filename = input("Please enter the filename where the messages are contained: ")
            messages_file = open(filename, 'r')
            filename = input("Please enter the filename where the encrypted messages will go: ")
            ciphertext_file = open(filename, 'w')

            # get the public key data
            n = 0
            b = 0
            i = 0
            for line in key_file:
                if i == 0:
                    n = int(line)
                    i += 1
                else:
                    b = int(line)
            key_file.close()
            # loop through the file, encode each line, and encrypt each line, printing the result to the ciphertext file
            start = clock()
            for line in messages_file:
                l = ''.join([i for i in line if i.isalpha()])
                ciphertext_file.write(str(rsa(n, b, encode(l))))
                ciphertext_file.write('\n')
            print("Operation complete in", clock() - start, "seconds.")
            ciphertext_file.close()
            messages_file.close()
        # Decrypt a string using a key input by the user (or taken in from a file)
        elif choice == 3:
            # Step 1: get the key from a file designated by the user (p is first line, q is second, a is third)
            filename = input("Please enter the filename where the private key is contained: ")
            key_file = open(filename, 'r')
            filename = input("Please enter the filename where the encrypted texts are contained: ")
            ciphertext_file = open(filename, 'r')
            filename = input("Please enter the filename where the decrypted texts will go: ")
            decrypted_file = open(filename, 'w')

            # Get our p, q, and a values from our private key file
            p = 0
            q = 0
            a = 0
            i = 0
            for line in key_file:
                if i == 0:
                    p = int(line)
                    i += 1
                elif i == 1:
                    q = int(line)
                    i += 1
                elif i == 2:
                    a = int(line)
            key_file.close()
            # For each line in our ciphertext_file, we need to decrypt then decode that line, writing the result to our
            # decrypted_file
            start = clock()
            for line in ciphertext_file:
                decrypted_file.write(str(decode(rsa(p * q, a, int(line)))))
                decrypted_file.write('\n')
            print("Operation complete in", clock() - start, "seconds.")
            ciphertext_file.close()
            decrypted_file.close()
        # Print a new copy of the menu
        elif choice == 4:
            return 0


main()
# Success on exiting, exit with code 0
exit(0)
