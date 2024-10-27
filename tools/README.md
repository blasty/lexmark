# Lexmark tools

Here you will find a small collection of tools that aid in unpacking/decrypting the Lexmark `.FLS` firmware upgrade blobs.

[`fw_decrypt.py`](fw_decrypt.py) can decrypt and unpack FLS containers. If you also want to be 
able to decrypt the squashFS (root) file systems for the most recent firmware updates
you will need to run [`wtm_oracle`](./wtm_oracle/) on a (rooted) printer.

[`wtm_oracle`](./wtm_oracle/) also offers some additional functionality which is mostly useful for people who want to dive deeper into WTM, this requires building/loading a [custom kernel module](./wtm_oracle/lkm) on your printer.

If you want to learn more about this additional rootfs encryption or the Marvell WTM usage by Lexmark in general; check out these two blog posts I wrote:
* [Retrofitting encrypted firmware is a Bad Idea™](https://haxx.in/posts/wtm-wtf/)
* [Let's PWN WTM!](https://haxx.in/posts/wtm-pwn/)
