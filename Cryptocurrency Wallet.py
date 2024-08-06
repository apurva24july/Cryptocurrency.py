import hashlib
from ecdsa import SigningKey, VerifyingKey, SECP256k1

# Generate a new private key and public key
def generate_keys():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key, public_key

# Create a transaction
class Transaction:
    def __init__(self, sender_public_key, recipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount
        self.signature = None

    def to_dict(self):
        return {
            'sender_public_key': self.sender_public_key.to_string().hex(),
            'recipient_public_key': self.recipient_public_key.to_string().hex(),
            'amount': self.amount
        }

    def sign_transaction(self, private_key):
        transaction_hash = self.calculate_hash()
        self.signature = private_key.sign(transaction_hash.encode())

    def calculate_hash(self):
        transaction_data = str(self.to_dict())
        return hashlib.sha256(transaction_data.encode()).hexdigest()

    def verify_transaction(self):
        if self.signature is None:
            return False
        transaction_hash = self.calculate_hash()
        return self.sender_public_key.verify(self.signature, transaction_hash.encode())

# Test the wallet functionality
private_key, public_key = generate_keys()
print(f"Private Key: {private_key.to_string().hex()}")
print(f"Public Key: {public_key.to_string().hex()}")

transaction = Transaction(public_key, public_key, 10)
transaction.sign_transaction(private_key)

print("Transaction Data:", transaction.to_dict())
print("Transaction Signature:", transaction.signature.hex())
print("Is the transaction valid?", transaction.verify_transaction())
