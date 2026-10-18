from PIL import Image, ImageDraw
import os
base="/Users/aralim/Desktop/Projekte/siegel/design/logo-entwuerfe"
out="/private/tmp/claude-501/-Users-aralim-Desktop/b9cbdf41-db59-4539-9e1d-f81d64e2d90a/scratchpad/jury-marke"
dirs=sorted(d for d in os.listdir(base) if os.path.isdir(os.path.join(base,d)))
# small sizes, nearest upscale x8 for 16, x4 for 32, plus native 1x
rows=[]
W=1400
sheet=Image.new("RGB",(W,len(dirs)*300+20),(236,236,236))
dr=ImageDraw.Draw(sheet)
for i,d in enumerate(dirs):
    y=10+i*300
    dr.text((10,y),d,fill=(0,0,0))
    x=10
    for f,scale in [("icon-16.png",8),("icon-32.png",4),("icon-128.png",1),("icon-klein-16.png",8),("icon-klein-32.png",4),("icon-16-ohne-klein.png",8)]:
        p=os.path.join(base,d,f)
        if not os.path.exists(p): continue
        im=Image.open(p).convert("RGBA")
        big=im.resize((im.width*scale,im.height*scale),Image.NEAREST)
        bg=Image.new("RGBA",big.size,(236,236,236,255)); bg.alpha_composite(big)
        sheet.paste(bg.convert("RGB"),(x,y+20))
        dr.text((x,y+20+big.height+4),f,fill=(0,0,0))
        x+=big.width+20
    # native sizes 1x
    for f in ["icon-16.png","icon-32.png"]:
        im=Image.open(os.path.join(base,d,f)).convert("RGBA")
        bg=Image.new("RGBA",im.size,(236,236,236,255)); bg.alpha_composite(im)
        sheet.paste(bg.convert("RGB"),(x,y+20)); x+=im.width+10
sheet.save(os.path.join(out,"klein.png"))
# marks
m=Image.new("RGB",(5*260+20,300),(255,255,255))
dr=ImageDraw.Draw(m)
for i,d in enumerate(dirs):
    im=Image.open(os.path.join(base,d,"mark-512.png")).convert("RGBA").resize((250,250),Image.LANCZOS)
    bg=Image.new("RGBA",im.size,(255,255,255,255)); bg.alpha_composite(im)
    m.paste(bg.convert("RGB"),(10+i*260,10)); dr.text((10+i*260,270),d,fill=(0,0,0))
m.save(os.path.join(out,"marks.png"))
