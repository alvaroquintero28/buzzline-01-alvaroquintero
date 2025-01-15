# buzzline-01-alvaroquintero

This project introduces streaming data. 
The Python language includes generators - we'll use this feature to generate some streaming buzzline messages. 
As the code runs, it will continuously update log file. 
We'll use a consumer to modify this log file and alert us when a special message is detected. 

## Task 1. Set Up Your Machine

First, you'll need to set up your machine. 
Detailed instructions by operating system are provided. 

1. Install Git.
2. Install Python **Version 3.11**.
3. Install VS Code.
4. Configure Git with user.name and user.email. 
5. Turn on VS Code File / Autosave.
6. Install VS Code Extensions (see instructions)

For detailed instructions, see:

- [SETUP-MAC-LINUX.md](docs/SETUP-MAC-LINUX.md)
- [SETUP-WINDOWS.md](docs/SETUP-WINDOWS.md)

## Python Versions (3.11 for this course)

The most current version of Python is 3.13. 
This course will use advanced tools (such as Kafka) that still require Python 3.11. 
You are encouraged to install both and practice multiple versions. 
If space is an issue, we only need 3.11 in this course. 
For more information, See [PYTHON-VERSIONS.md](docs/PYTHON-VERSIONS.md).

## Task 2. Copy This Example Project & Change `case` to `yourname` (buzzline-01-alvaroquintero)

Once the tools are installed, copy/fork this project into your GitHub account
and create your own version of this project to run and experiment with. 
Name it **buzzline-01-alvaroquintero** where yourname is something unique to you.
Follow the instructions in [FORK-THIS-REPO.md](docs/FORK-THIS-REPO.md).

## Task 3. Manage Local Project Virtual Environment

Python needs a place to keep all the free code we download and use in our projects. 
For this, we create a .venv folder to hold our local project virtual environment. 
We create this folder (just once), activate it, and install additional packages listed in requirements.txt. 

Important: After creating, activating, and installing packages into .venv, 
we must remember to activate .venv every time we open a new terminal. 

Follow the instructions in [MANAGE-VENV.md](docs/MANAGE-VENV.md) to:
1. Create your .venv
2. Activate .venv
3. Install the required dependencies using requirements.txt.

The instructions are repeated in requirements.txt as this file exists in all our projects. 

## Task 4. Generate Streaming Data (Terminal 1)

Now we'll generate some streaming data. 
By the way - you've done 90% of the hard work before we even look at code. 
Congratulations!

In VS Code, open a terminal.
Use the commands below to activate .venv, and run the generator as a module. 
To learn more about why we run our Python file as a module, see [PYTHON-PKG-IMPORTS](docs/PYTHON-PKG-IMPORTS.md) 

Windows PowerShell:

```shell
.venv\Scripts\activate
py -m producers.basic_producer_alvaro
```

Mac/Linux:
```zsh
source .venv/bin/activate
python3 -m producers.basic_producer_alvaro
```

## Task 5. Monitor an Active Log File (Terminal 2)

A common streaming task is monitoring a log file as it is being written. 
This project has a consumer that reads and processes our own log file as log messages arrive. 

In VS Code, open a NEW terminal in your root project folder. 
Use the commands below to activate .venv, and run the file as a module. 

Windows:
```shell
.venv\Scripts\activate
py -m consumers.basic_consumer_alvaro
```

Mac/Linux:
```zsh
source .venv/bin/activate
python3 -m consumers.basic_consumer_alvaro
```

## Save Space
To save disk space, you can delete the .venv folder when not actively working on this project.
We can always recreate it, activate it, and reinstall the necessary packages later. 
Managing Python virtual environments is a necessary and valuable skill. 
We will get a good amount of practice. 

## License
This project is licensed under the MIT License as an example project. 
You are encouraged to fork, copy, explore, and modify the code as you like. 
See the [LICENSE](LICENSE.txt) file for more.
