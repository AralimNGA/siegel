from PIL import Image, ImageDraw
import os
base=os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),"..","..","logo-entwuerfe"))
dirs=sorted(d for d in os.listdir(base) if os.path.isdir(os.path.join(base,d)))
others=["Safari","Mail","Notes","Calendar","Passwords","Terminal","Xcode","Notion"]
S=112
def icon(p): return Image.open(p).convert("RGBA").resize((S,S),Image.LANCZOS)
oth=[icon(f"dock/{o}.png") for o in others]
cands=[icon(f"t_{d}.png") for d in dirs]
# candidate PNG has #EDEDED background -> make it transparent via the 1024 svg render? use icon.svg render instead
W=len(others)+1
img=Image.new("RGB",(W*(S+10)+40, 2*len(dirs)*(S+30)+20),(255,255,255))
dr=ImageDraw.Draw(img)
y=10
for mode,bg in [("hell",(225,225,228)),("dunkel",(40,40,44))]:
  for i,d in enumerate(dirs):
    dr.rounded_rectangle((10,y,W*(S+10)+30,y+S+20),radius=24,fill=bg)
    x=20
    row=oth[:4]+[None]+oth[4:]
    for o in row:
      im = cands[i] if o is None else o
      layer=Image.new("RGBA",img.size,(0,0,0,0)); layer.paste(im,(x,y+10),im)
      base_img=img.convert("RGBA"); base_img.alpha_composite(layer); img=base_img.convert("RGB"); dr=ImageDraw.Draw(img)
      x+=S+10
    y+=S+30
img.save("dock.png")
