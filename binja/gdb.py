def extract(str):
    try:
        return int(str, 16)
    except ValueError:
        return None


mapping = []
data = gdb.execute("info proc mappings", False, True).split("\n")[3:-1]
for l in data:
    columns = l.split()
    ret = [extract(x.strip()) for x in columns]
    ret[4] = columns[4]
    # print(ret)
    mapping.append(ret)


frame = gdb.newest_frame()
while frame is not None:
    if frame.type() != gdb.NORMAL_FRAME:
        frame = frame.older()
        continue
    pc = frame.pc()
    for m in mapping:
        if pc >= m[0] and pc < m[1]:
            print(hex(pc - m[0] + m[3]), m[4])
            break
    frame = frame.older()
