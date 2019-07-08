# Python 3

import json, argparse

parser = argparse.ArgumentParser(
    description="Parse json output of the KRF LLVM pass into a triaged form"
)
parser.add_argument("-json", dest="json", action="store_true", help="outputs json")
parser.add_argument(
    "files", metavar="filename", type=str, nargs="+", help="list of .json files to process"
)
args = parser.parse_args()
JSON = args.json  # sets output to json

LOW = 0
MED = 1
HIGH = 2
UNK = 3

LOW_SEV = [
    "clock_gettime",
    "time",
    "gettimeofday",
    "kill",
    "sigaction",
    "rt_sigaction",
    "sigprocmask",
    "rt_sigprocmask",
    "sigreturn",
    "rt_sigreturn",
    "ioctl",
    "sched_yield",
    "shmdt",
    "setpgid",
    "dup",
    "pause",
]
MED_SEV = [
    "unlink",
    "close",
    "open",
    "stat",
    "fstat",
    "lstat",
    "select",
    "poll",
    "munmap",
    "mincore",
    "pipe",
    "pipe2",
    "madvise",
    "shmctl",
    "nanosleep",
    "sendto",
]
HIGH_SEV = [
    "read",
    "write",
    "creat",
    "openat",
    "lseek",
    "pread",
    "pwrite",
    "fread",
    "readv",
    "writev",
    "readlink",
    "syscall",
    "execve",
    "mmap",
    "mprotect",
    "mremap",
    "msync",
    "mlock",
    "mlockall",
    "fork",
    "clone",
    "chmod",
    "fchmod",
    "chown",
    "fchown",
    "brk",
    "access",
    "faccessat",
    "shmget",
    "dup2",
    "dup3",
    "fcntl",
]

low_arr = []
med_arr = []
high_arr = []
unk_arr = []


def severity(call):
    if call in LOW_SEV:
        return LOW
    elif call in MED_SEV:
        return MED
    elif call in HIGH_SEV:
        return HIGH
    return UNK


def formatCallData(data):
    s = data["call"]
    s += " in " + data["function"] + "()"
    if "line" in data and "file" in data and "dir" in data:
        s += " @ " + data["dir"] + "/" + data["file"] + ":" + str(data["line"])
    else:
        s += " @ " + data["module"]
    return s


def formatObj(arr):
    obj = {}
    for i in arr:
        if i["module"] not in obj:
            obj[i["module"]] = {}
        if i["call"] not in obj[i["module"]]:
            obj[i["module"]][i["call"]] = []
        d = {"call": i["call"], "function": i["function"], "module": i["module"]}
        if "line" in i and "file" in i and "dir" in i:
            d["line"] = i["line"]
            d["file"] = i["file"]
            d["dir"] = i["dir"]
        obj[i["module"]][i["call"]].append(d)
    return obj


def analyze(data):
    if not isinstance(data, list):
        return
    for item in data:
        if not item["errno_checked"]:
            sev = severity(item["call"])
            if sev == LOW:
                low_arr.append(item)
            elif sev == MED:
                med_arr.append(item)
            elif sev == HIGH:
                high_arr.append(item)
            else:
                unk_arr.append(item)


def main():
    global low_arr, med_arr, high_arr, unk_arr
    for fname in args.files:
        if not JSON:
            print("***", fname, "***")
        with open(fname) as f:
            json_data = f.read()
        data = json.loads(json_data)
        analyze(data["syscalls"])
    if not JSON:
        if low_arr:
            # print("[ ] Low severity:")
            for i in low_arr:
                print("LOW: ", formatCallData(i))
            low_arr = []
        if med_arr:
            # print("[-] Medium severity:")
            for i in med_arr:
                print("MED: ", formatCallData(i))
            med_arr = []
        if high_arr:
            # print("[x] High severity:")
            for i in high_arr:
                print("HIGH:", formatCallData(i))
            high_arr = []
        if unk_arr:
            # print("[?] Unknown severity:")
            for i in unk_arr:
                print("UNK: ", formatCallData(i))
            unk_arr = []
    else:
        root = {}
        if low_arr:
            root["low"] = formatObj(low_arr)
            low_arr = []
        if med_arr:
            root["med"] = formatObj(med_arr)
            med_arr = []
        if high_arr:
            root["high"] = formatObj(high_arr)
            high_arr = []
        if unk_arr:
            root["unk"] = formatObj(unk_arr)
            unk_arr = []
        print(json.dumps(root))


main()
