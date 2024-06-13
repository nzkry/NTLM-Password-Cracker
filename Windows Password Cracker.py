import itertools
import multiprocessing
import os
import string
import threading
import time
import logging
import pickle
from passlib.hash import nthash

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Cracker:
    ALPHA_LOWER = (string.ascii_lowercase,)
    ALPHA_UPPER = (string.ascii_uppercase,)
    ALPHA_MIXED = (string.ascii_lowercase, string.ascii_uppercase)
    PUNCTUATION = (string.punctuation,)
    NUMERIC = (''.join(map(str, range(0, 10))),)
    ALPHA_LOWER_NUMERIC = (string.ascii_lowercase, ''.join(map(str, range(0, 10))))
    ALPHA_UPPER_NUMERIC = (string.ascii_uppercase, ''.join(map(str, range(0, 10))))
    ALPHA_MIXED_NUMERIC = (string.ascii_lowercase, string.ascii_uppercase, ''.join(map(str, range(0, 10))))
    ALPHA_LOWER_PUNCTUATION = (string.ascii_lowercase, string.punctuation)
    ALPHA_UPPER_PUNCTUATION = (string.ascii_uppercase, string.punctuation)
    ALPHA_MIXED_PUNCTUATION = (string.ascii_lowercase, string.ascii_uppercase, string.punctuation)
    NUMERIC_PUNCTUATION = (''.join(map(str, range(0, 10))), string.punctuation)
    ALPHA_LOWER_NUMERIC_PUNCTUATION = (string.ascii_lowercase, ''.join(map(str, range(0, 10))), string.punctuation)
    ALPHA_UPPER_NUMERIC_PUNCTUATION = (string.ascii_uppercase, ''.join(map(str, range(0, 10))), string.punctuation)
    ALPHA_MIXED_NUMERIC_PUNCTUATION = (
        string.ascii_lowercase, string.ascii_uppercase, ''.join(map(str, range(0, 10))), string.punctuation
    )

    def __init__(self, hash, charset, progress_interval, core_label, max_length=20):
        self.__charset = charset
        self.__curr_iter = 0
        self.__prev_iter = 0
        self.__curr_val = ""
        self.__progress_interval = progress_interval
        self.__hash_type = "ntlm"
        self.__hash = hash
        self.__hashers = {}
        self.__max_length = max_length
        self.__found = False
        self.__core_label = core_label
        self.__checkpoint_file = f"checkpoint_{core_label}.pkl"
        self.__init_hasher()
        self.__load_checkpoint()

    def __init_hasher(self):
        self.__hashers[self.__hash_type] = nthash

    def __load_checkpoint(self):
        if os.path.exists(self.__checkpoint_file):
            with open(self.__checkpoint_file, 'rb') as f:
                state = pickle.load(f)
                self.__curr_iter = state['curr_iter']
                self.__curr_val = state['curr_val']
                logging.info(f"[Stopped at: {self.__core_label}] - Resuming from checkpoint: Iteration {self.__curr_iter}, Value {self.__curr_val}")

    def __save_checkpoint(self):
        state = {
            'curr_iter': self.__curr_iter,
            'curr_val': self.__curr_val
        }
        with open(self.__checkpoint_file, 'wb') as f:
            pickle.dump(state, f)

    @staticmethod
    def __encode_utf16le(data):
        return data.encode("utf-16le")

    @staticmethod
    def __search_space(charset, maxlength, start, step):
        for i in range(1, maxlength + 1):
            for idx, candidate in enumerate(itertools.product(charset, repeat=i)):
                if idx % step == start:
                    yield ''.join(candidate)

    def __attack(self, found, max_length, start, step):
        self.start_reporting_progress(found)
        for value in self.__search_space(self.__charset, max_length, start, step):
            if found.value:
                break
            if self.__hash == nthash.hash(value):
                with found.get_lock():
                    found.value = 1
                logging.info(f"[Completed at: {self.__core_label}] - Match found! Password is {value}")
                self.__stop_other_processes(found)
                return

            self.__curr_iter += 1
            self.__curr_val = value

            if self.__curr_iter % 1000 == 0:  # Save checkpoint every 1000 iterations
                self.__save_checkpoint()

        self.stop_reporting_progress()

    def __stop_other_processes(self, found):
        self.stop_reporting_progress()
        with found.get_lock():
            found.value = 2
        if os.path.exists(self.__checkpoint_file):
            os.remove(self.__checkpoint_file)

    @staticmethod
    def work(work_q, found, max_length, start, step):
        obj = work_q.get()
        obj.__attack(found, max_length, start, step)

    def start_reporting_progress(self, found):
        if not found.value:
            self.__progress_timer = threading.Timer(self.__progress_interval, self.start_reporting_progress, [found])
            self.__progress_timer.start()
            logging.info(
                f"[Running on: {self.__core_label}] Charset: {self.__charset}, Iteration: {self.__curr_iter}, Trying: {self.__curr_val}, Hashes/sec: {self.__curr_iter - self.__prev_iter}"
            )
            self.__prev_iter = self.__curr_iter

    def stop_reporting_progress(self):
        if hasattr(self, '__progress_timer'):
            self.__progress_timer.cancel()
        if not self.__found:
            self.__found = True

if __name__ == "__main__":
    character_sets = {
        "01": Cracker.ALPHA_LOWER,
        "02": Cracker.ALPHA_UPPER,
        "03": Cracker.ALPHA_MIXED,
        "04": Cracker.NUMERIC,
        "05": Cracker.ALPHA_LOWER_NUMERIC,
        "06": Cracker.ALPHA_UPPER_NUMERIC,
        "07": Cracker.ALPHA_MIXED_NUMERIC,
        "08": Cracker.PUNCTUATION,
        "09": Cracker.ALPHA_LOWER_PUNCTUATION,
        "10": Cracker.ALPHA_UPPER_PUNCTUATION,
        "11": Cracker.ALPHA_MIXED_PUNCTUATION,
        "12": Cracker.NUMERIC_PUNCTUATION,
        "13": Cracker.ALPHA_LOWER_NUMERIC_PUNCTUATION,
        "14": Cracker.ALPHA_UPPER_NUMERIC_PUNCTUATION,
        "15": Cracker.ALPHA_MIXED_NUMERIC_PUNCTUATION
    }

    prompt = "Specify Password Character Set to Crack. Choose 1-15:{}{}".format(os.linesep, os.linesep)
    for key, value in sorted(character_sets.items()):
        prompt += "{}. {}{}".format(key, ''.join(value), os.linesep)

    prompt += "{}Character Set: ".format(os.linesep)

    while True:
        try:
            charset = input(prompt).zfill(2)
            selected_charset = character_sets[charset]
        except KeyError:
            print("{}Please select a valid character set{}".format(os.linesep, os.linesep))
            continue
        else:
            break

    password_length = 20

    prompt = "{}Specify the NTLM hash to be attacked: ".format(os.linesep)

    while True:
        try:
            user_hash = input(prompt)
        except ValueError:
            print("{}Something is wrong with the format of the hash. Please enter a valid NTLM hash".format(os.linesep))
            continue
        else:
            break

    logging.info(f"Trying to crack hash {user_hash}")
    processes = []
    work_queue = multiprocessing.Queue()
    found = multiprocessing.Value('i', 0)
    progress_interval = 3
    num_threads = multiprocessing.cpu_count()  # Automatically use the number of available CPU cores
    start_time = time.time()

    for i in range(num_threads):
        core_label = f"Core {i}"
        cracker = Cracker(user_hash.lower(), ''.join(selected_charset), progress_interval, core_label, password_length)
        p = multiprocessing.Process(target=Cracker.work, args=(work_queue, found, password_length, i, num_threads))
        processes.append(p)
        work_queue.put(cracker)
        p.start()

    for p in processes:
        p.join()

    if found.value == 1:
        logging.info("Password found")
    elif found.value == 0:
        logging.info("No matches found")

    logging.info(f"Took {time.time() - start_time} seconds")
