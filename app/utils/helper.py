from hashids import Hashids

hashids = Hashids(min_length=8, salt='ArNoNA9123PLjHnKANEIams2NA')

def encode_id(id):
    return hashids.encode(id)

def decode_id(hashid):
    decoded = hashids.decode(hashid)
    return decoded[0] if decoded else None
