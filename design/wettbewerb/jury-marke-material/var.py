import sys, math, subprocess, importlib.util
spec=importlib.util.spec_from_file_location("b","/Users/aralim/Desktop/Projekte/siegel/design/logo-entwuerfe/03-monogramm/bauen.py")
b=importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
src=open(spec.origin).read()
R="/private/tmp/claude-501/-Users-aralim-Desktop/b9cbdf41-db59-4539-9e1d-f81d64e2d90a/scratchpad/svg_render"
def mk(rkf, name, cxo=3):
    code=src.replace("rk = 2.5 * u","rk = %r * u"%rkf).replace("cx - 3 * u, cy - 4 * u","cx - %r * u, cy - 4 * u"%cxo).replace("cx + 3 * u, cy + 4 * u","cx + %r * u, cy + 4 * u"%cxo)
    ns={"__name__":"x","__file__":spec.origin}; exec(code,ns)
    open(f"v_{name}_mark.svg","w").write(ns["mark_svg"]())
    open(f"v_{name}_icon.svg","w").write(ns["icon_svg"]())
    subprocess.run([R,f"v_{name}_mark.svg",f"v_{name}_mark.png","320","white"],check=True,stdout=subprocess.DEVNULL)
    for px in (128,32):
        subprocess.run([R,f"v_{name}_icon.svg",f"v_{name}_icon{px}.png",str(px),"#EDEDED"],check=True,stdout=subprocess.DEVNULL)
mk(2.5,"a"); mk(2.75,"b"); mk(3.0,"c"); mk(3.0,"d",cxo=2.5)
from PIL import Image
names="abcd"
img=Image.new("RGB",(4*340,340+140+10),(255,255,255))
for i,n in enumerate(names):
    img.paste(Image.open(f"v_{n}_mark.png").convert("RGB"),(10+i*340,10))
    img.paste(Image.open(f"v_{n}_icon128.png").convert("RGB"),(10+i*340,340))
    s=Image.open(f"v_{n}_icon32.png").convert("RGB"); img.paste(s.resize((128,128),Image.NEAREST),(150+i*340,340)); img.paste(s,(290+i*340,340))
img.save("varianten.png")
