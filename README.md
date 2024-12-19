# EverPwnage

**iOS 8.0-9.0.2 Jailbreak for 32-bit Devices**

## Usage

Download and sideload the IPA from the [latest release](https://github.com/LukeZGD/EverPwnage/releases/latest).

## Supported Devices

All 32-bit iOS devices that support iOS 8 and 9:
- **iPhone**: 4S, 5, 5C
- **iPad**: 2, 3, 4, mini 1
- **iPod touch**: 5

## iOS 9.0.x Support

Support for iOS 9.0.x is **experimental and limited**. It is limited to A6(X) devices only (iPhone 5, 5C, iPad 4) due to issues with A5(X) devices.

## Jailbreak Modes

EverPwnage has an "Install Untether" toggle, which controls the installation of daibutsu untether:

- The toggle is enabled by default on compatible devices for a fully untethered jailbreak.
- Users can manually disable the toggle if they prefer to remain semi-untethered.
- On incompatible devices (iOS 9.0.x devices or A5(X) devices running iOS 8.0-8.2), the toggle is automatically disabled, limiting these devices to a semi-untethered jailbreak.

## Untether Compatibility

- iOS 8.0-8.4.1: A6(X) devices
- iOS 8.3-8.4.1: A5(X) devices

For all other configurations, the option to untether is not available.

## Switching from Other Jailbreaks

If you are using other iOS 8 jailbreaks like EtasonJB, HomeDepot, or openpwnage, you can switch to EverPwnage. Jailbreaking with EverPwnage and keeping the "Install Untether" toggle enabled will switch your device to daibutsu untether (if supported).

Do **not** use EverPwnage if your device is already jailbroken with:

- Pangu8
- Pangu9
- TaiG
- PPJailbreak
- wtfis (not for 32-bit devices)

These jailbreaks are already untethered and/or incompatible with 32-bit devices in the case of wtfis.

## Building

This project is built using Xcode 10.1 and macOS High Sierra 10.13.6.

## Credits

- Thanks to [Merculous](https://github.com/Merculous) for testing and feedback
- exploit: [sock_port_2_legacy](https://github.com/kok3shidoll/sock_port_2_legacy/tree/ios8)
- untether and patches: [daibutsu untether](https://kok3shidoll.github.io/info/jp.daibutsu.untether841/indexv2.html) ([GitHub repo](https://github.com/kok3shidoll/daibutsu))
- got the IOKit stuff from: [wtfis](https://github.com/TheRealClarity/wtfis)
- base of this jailbreak: [openpwnage](https://github.com/0xilis/openpwnage)
