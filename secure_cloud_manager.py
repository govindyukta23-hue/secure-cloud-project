
import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecureCloudManager:
    def __init__(self, block_size_mb=1):
        """Initialize the manager with the required block size."""
        self.block_size = int(block_size_mb * 1024 * 1024)

    def segment_and_encrypt(self, source_file_path, output_dir, encryption_key):
        """
        Split a file into blocks and encrypt each block using AES-256-GCM.
        Each encrypted block contains its 12-byte nonce followed by ciphertext
        and the authentication tag.
        """
        os.makedirs(output_dir, exist_ok=True)

        aesgcm = AESGCM(encryption_key)
        manifest = []
        file_index = 0

        print(f"[+] Initializing segmentation for: {source_file_path}")

        with open(source_file_path, "rb") as src:
            while True:
                chunk = src.read(self.block_size)

                if not chunk:
                    break

                # Generate a unique 12-byte nonce for this block.
                nonce = secrets.token_bytes(12)

                # Encrypt the block and generate its authentication tag.
                encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)

                block_filename = f"part_{file_index}.enc"
                block_path = os.path.join(output_dir, block_filename)

                # Store the nonce before the encrypted data.
                with open(block_path, "wb") as out_block:
                    out_block.write(nonce + encrypted_chunk)

                manifest.append(block_filename)

                print(
                    f" -> Encrypted block {file_index}: "
                    f"{len(chunk)} bytes"
                )

                file_index += 1

        print(
            f"[+] Successfully encrypted {file_index} blocks.\n"
        )

        return manifest

    def decrypt_and_reassemble(
        self,
        block_dir,
        manifest,
        target_output_path,
        encryption_key,
    ):
        """
        Decrypt and authenticate each encrypted block, then reconstruct
        the original file in the correct order.
        """
        aesgcm = AESGCM(encryption_key)

        print(
            f"[+] Starting secure download and reassembly: "
            f"{target_output_path}"
        )

        # Write to a temporary file so a failed authentication does not
        # leave a partially reconstructed output at the target path.
        temp_output_path = target_output_path + ".tmp"

        try:
            with open(temp_output_path, "wb") as final_file:
                for block_filename in manifest:
                    block_path = os.path.join(block_dir, block_filename)

                    with open(block_path, "rb") as block_file:
                        raw_data = block_file.read()

                    # A nonce is 12 bytes. AES-GCM also needs an
                    # authentication tag, so reject incomplete blocks.
                    if len(raw_data) < 12 + 16:
                        raise ValueError(
                            f"Encrypted block is incomplete: "
                            f"{block_filename}"
                        )

                    nonce = raw_data[:12]
                    encrypted_payload = raw_data[12:]

                    # Decryption raises InvalidTag if authentication fails.
                    decrypted_chunk = aesgcm.decrypt(
                        nonce, encrypted_payload, None
                    )

                    final_file.write(decrypted_chunk)

                    print(
                        f" -> Authenticated and restored: "
                        f"{block_filename}"
                    )

            # Replace the destination only after every block succeeds.
            os.replace(temp_output_path, target_output_path)

            print(
                "[+] File authentication and reconstruction completed."
            )

        except Exception:
            if os.path.exists(temp_output_path):
                os.remove(temp_output_path)
            raise


if __name__ == "__main__":
    # Generate a fresh 256-bit AES key for this demonstration.
    secret_key = AESGCM.generate_key(bit_length=256)

    # Each block will be 0.5 MB (512 KB).
    manager = SecureCloudManager(block_size_mb=0.5)

    # Define the sample file and output locations.
    project_dir = os.getcwd()

    sample_payload = os.path.join(
        project_dir, "portfolio_data.raw"
    )

    cloud_vault_dir = os.path.join(
        project_dir, "mock_cloud_storage"
    )

    restored_asset = os.path.join(
        project_dir, "downloaded_portfolio_data.raw"
    )

    # Create a sample 2 MB file if it does not already exist.
    if not os.path.exists(sample_payload):
        print("[+] Creating a 2 MB sample file...")

        with open(sample_payload, "wb") as sample_file:
            sample_file.write(os.urandom(2 * 1024 * 1024))

    # Read the original file for the final integrity comparison.
    with open(sample_payload, "rb") as sample_file:
        original_data = sample_file.read()

    # Encrypt the file into individual blocks.
    block_manifest = manager.segment_and_encrypt(
        sample_payload,
        cloud_vault_dir,
        secret_key,
    )

    # Decrypt and reconstruct the original file.
    manager.decrypt_and_reassemble(
        cloud_vault_dir,
        block_manifest,
        restored_asset,
        secret_key,
    )

    # Verify that the reconstructed file matches the original.
    with open(restored_asset, "rb") as restored_file:
        restored_data = restored_file.read()

    if original_data == restored_data:
        print("[SUCCESS] Original and reconstructed files match.")
    else:
        print("[ERROR] File verification failed.")
