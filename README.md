# SecureNote

SecureNote is an encrypted note-taking application designed to securely store your notes. With its user-friendly interface, you can easily create, edit, and manage your notes. All your data is protected by encryption, ensuring that your information remains safe.

## Features

- **Encrypted Notes**: All your notes are protected using a strong encryption algorithm. Only you can access and view them.
- **Password Protection**: Upon first launch, you will be prompted to set a strong password. This password controls access to your notes.
- **Note Management**: 
  - **Add New Note**: Create new notes by adding a title, content, and tags.
  - **Update Note**: Update existing notes through the title, content, or tags.
  - **Delete Note**: Easily delete notes you no longer need.
  - **Search Notes**: Quickly search for notes based on specific keywords.
- **Backup Options**: Various methods are available for backing up your data and restoring it when necessary.
- **Tagging**: Add tags to your notes for better organization and quick access to the notes you are looking for.
- **Database Management**: Change the database location, perform backups, and restore processes.

## Installation

### Requirements

- Python 3.x
- The following libraries:
  - `cryptography`
  - `sqlite3`
  - `getpass`
  - `hashlib`
  - `shutil`
  
### Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/glitchidea/ConsolMP.git
   cd ConsolMP
   ```

2. **Install Required Dependencies**:
   Install the required libraries using:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**:
   To start the application, use:
   ```bash
   python app.py
   ```

## Usage

- When the application opens, you will be prompted to set a password for the first time. This password will be used to access your notes.
- The main menu offers the following options:
  1. **New Note**: Creates a new note.
  2. **All Notes**: Displays all saved notes.
  3. **Search Note**: Allows you to search for notes by a specific keyword.
  4. **Delete Note**: Deletes the note with the specified ID.
  5. **Update Note**: Updates an existing note.
  6. **Settings**: Manage application settings, perform backup and restore operations.
  0. **Exit**: Exits the application.

## Security

- The application uses a strong encryption algorithm to store your notes securely. Each note is accessible only with the password you set.
- The password file and key file are protected to ensure the security of the application. Don't forget to back up these files.

## Contributing

If you would like to contribute, please follow these steps:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-xyz`).
3. Make your changes and commit them (`git commit -m 'Add some feature'`).
4. Push your branch (`git push origin feature-xyz`).
5. Create a pull request.
