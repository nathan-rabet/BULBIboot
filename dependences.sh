if [ -x "$(command -v apt)" ]; then
    sudo apt update
    sudo apt install -y gcc-aarch64-linux-gnu
    sudo apt install -y bison
    sudo apt install -y flex
    sudo apt install qemu-system-arm
    sudo apt install openssl
    sudo apt install libgcc-12-dev-arm64-cross
elif [ -x "$(command -v pacman)" ]; then
    sudo pacman -Syu
    sudo pacman -S --needed --noconfirm gcc-aarch64-linux-gnu
    sudo pacman -S --needed --noconfirm bison
    sudo pacman -S --needed --noconfirm flex
    sudo pacman -S --needed --noconfirm qemu
    sudo pacman -S --needed --noconfirm openssl
    sudo pacman -S --needed --noconfirm libgcc-12-dev-arm64-cross
elif [ -x "$(command -v dnf)" ]; then
    sudo dnf update
    sudo dnf install -y gcc-aarch64-linux-gnu
    sudo dnf install -y bison
    sudo dnf install -y flex
    sudo dnf install -y qemu-system-arm
    sudo dnf install -y openssl
    sudo dnf install -y libgcc-12-dev-arm64-cross
elif [ -x "$(command -v yum)" ]; then
    sudo yum update
    sudo yum install -y gcc-aarch64-linux-gnu
    sudo yum install -y bison
    sudo yum install -y flex
    sudo yum install -y qemu-system-arm
    sudo yum install -y openssl
    sudo yum install -y libgcc-12-dev-arm64-cross
else
    echo "Unsupported OS"
    exit 1
fi
