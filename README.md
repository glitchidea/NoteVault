# NoteVault

NoteVault is a secure, console-based note management application built in Python. It allows users to create, read, update, and delete notes while ensuring data security through encryption and backup features.

## Features

- **Create Notes:** Easily add notes with a title, content, and tags.
- **View Notes:** Display a list of all your notes with details.
- **Update Notes:** Modify existing notes as needed.
- **Delete Notes:** Remove notes you no longer need.
- **Tagging System:** Organize your notes with tags for easy retrieval.
- **Search Functionality:** Find notes by keywords in titles or content.
- **Secure Storage:** Notes are encrypted for maximum privacy.
- **Backup and Restore:** Create backups of your notes and restore them when necessary.
- **Configuration Options:** Change settings such as database location and encryption keys.

## Installation

1. Ensure that Python 3.x is installed on your system.
2. Install the required dependencies:
   ```bash
   pip install cryptography
   ```
3. Clone the repository:
   ```bash
   git clone https://github.com/glitchidea/NoteVault.git
   cd NoteVault
   ```
4. Run the application:
   ```bash
   python main.py
   ```

## Usage

1. **Start the Application:** Execute `main.py` to launch NoteVault.
2. **Main Menu Options:**
   - 1: Create Note
   - 2: View Notes
   - 3: Update Note
   - 4: Delete Note
   - 5: Search Notes
   - 6: Backup and Restore
   - 0: Exit
3. **Managing Your Notes:** Follow the prompts in the menu to manage your notes effectively.

## Security

### Data Encryption

- **Encryption Mechanism:** NoteVault uses the `cryptography` library to encrypt all note data, ensuring that sensitive information is protected.
- **Key Management:** An encryption key is generated and stored securely, required for both encrypting and decrypting notes.

### Password Protection

- **User Authentication:** On the first launch, users must set a password. This password is used to secure access to notes.
- **Integrity Checks:** The application verifies the integrity of the password file using hash checks to prevent tampering.

### Backup and Restore

- **Backup Functionality:** Users can create backups of their notes and encryption keys to avoid data loss.
- **Restore Functionality:** Restore notes and settings from backups easily whenever needed.
