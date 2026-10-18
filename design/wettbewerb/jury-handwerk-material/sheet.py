import os
from PIL import Image, ImageDraw
B='/Users/aralim/Desktop/Projekte/siegel/design/logo-entwuerfe'
ds=['01-wachssiegel','02-gitter','03-monogramm','04-riegel','05-kristall']
def ld(p):
    return Image.open(p).convert('RGBA') if os.path.exists(p) else None
# Sheet A: pixel zoom of 16/32 (official + klein/ohne-klein)
cols=[('icon-16.png',12),('icon-klein-16.png',12),('icon-16-ohne-klein.png',12),('icon-32.png',6),('icon-klein-32.png',6)]
W=len(cols)*210+20; H=len(ds)*210+20
sh=Image.new('RGB',(W,H),(200,200,200))
for i,d in enumerate(ds):
    for j,(f,s) in enumerate(cols):
        im=ld(f'{B}/{d}/{f}')
        if im is None: continue
        im=im.resize((im.width*s,im.height*s),Image.NEAREST)
        bg=Image.new('RGBA',im.size,(237,237,237,255)); bg.alpha_composite(im)
        sh.paste(bg.convert('RGB'),(10+j*210,10+i*210))
sh.save('sheetA_pixelzoom.png')
# Sheet B: actual sizes 16,32,64,128 on light gray, plus 2x zoomed (smooth) to emulate retina viewing
W=900; H=len(ds)*150+20
sh=Image.new('RGB',(W,H),(237,237,237))
for i,d in enumerate(ds):
    x=10; y=10+i*150
    for f in ['icon-16.png','icon-32.png',None,'icon-128.png']:
        im=ld(f'{B}/{d}/{f}') if f else ld(f'icon-{d}-64.png')
        sh.paste(im,(x,y),im); x+=im.width+20
    for px in [24,44,88]:
        im=ld(f'mark-{d}-{px}.png'); bg=Image.new('RGBA',im.size,(255,255,255,255)); bg.alpha_composite(im)
        sh.paste(bg.convert('RGB'),(x,y)); x+=im.width+20
sh.save('sheetB_echtgroesse.png')
# Sheet C: Dock row at 128 (64pt @2x) each, plus lock screen 176 (88pt@2x) on white
W=5*150+20; H=150+200+20
sh=Image.new('RGB',(W,H),(255,255,255))
dr=ImageDraw.Draw(sh); dr.rectangle([0,0,W,160],fill=(225,228,232))
for i,d in enumerate(ds):
    im=ld(f'{B}/{d}/icon-128.png'); sh.paste(im,(10+i*150,16),im)
    im=ld(f'mark-{d}-88.png'); bg=Image.new('RGBA',im.size,(255,255,255,255)); bg.alpha_composite(im)
    sh.paste(bg.convert('RGB'),(10+i*150+20,200))
sh.save('sheetC_dock_lock.png')
