import requests
import hashlib  # built-in module
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char    # passing first 5 char of SHA-1 password hash to param
    res = requests.get(url)         # now we have a Response object called 'res'
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res       # all password hashes beginning with the searched prefix are returned alongside prevalence counts
    # in this Response object


def get_password_leaks_count(hashes, hash_to_check):
    # hashes.text returns a string representation of the data payload excluding the searched prefix
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:     # loop through this generator object
        if h == hash_to_check:
            return count        # return number of times this password has been leaked
    return 0


def pwned_api_check(password):  # input actual password
    sh1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sh1password[:5], sh1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'Done!'

                                  
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
