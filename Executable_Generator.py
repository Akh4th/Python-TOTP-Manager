import shutil
import subprocess
import sys
import os


def check_and_install_pyinstaller():
    package_name = 'pyinstaller'
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'show', package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print(f"{package_name} is already installed.")
    except subprocess.CalledProcessError:
        print(f"{package_name} is not installed. Installing...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package_name])


def confirm_and_generate_executable():
    response = input("Are you sure you want to generate an executable? (yes/no): ").strip().lower()
    while type(response) != str or response.lower() not in ['yes', 'y', 'no', 'n']:
        response = input("Wrong input, please use yes/no only.\nAre you sure you want to generate an executable : ")
    if response in ['yes', 'y']:
        try:
            check_and_install_pyinstaller()
            current_dir = os.path.dirname(os.path.abspath(__file__))
            subprocess.run(['pyinstaller', '--onefile', '--windowed', '--icon=logo.ico', '--distpath', current_dir, 'main.py'], check=True)
            build_dir = os.path.join(current_dir, 'build')
            if os.path.exists(build_dir):
                shutil.rmtree(build_dir)
            os.remove('main.spec')
            print("Executable generated successfully.")
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while generating the executable: {e}")
    else:
        print("Operation cancelled.")


if __name__ == '__main__':
    confirm_and_generate_executable()
