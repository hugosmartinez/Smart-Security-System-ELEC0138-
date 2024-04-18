def verifyInfo(data):
    for key in data:
        if data[key] == "":
            return False
    return True