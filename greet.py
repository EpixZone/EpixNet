def grad(n):
    colors = [
        (0x31, 0xBD, 0xC6),
        (0x8A, 0x4B, 0xDB),
        (0x6B, 0x3A, 0xB8),
        (0x4C, 0x29, 0x95),
        (0x24, 0x1F, 0x90),
        
    ]

    color_index = (n // 2) % len(colors)
    r, g, b = colors[color_index]

    return f'#{r:02x}{g:02x}{b:02x}'

def fancy_greet(version):
    from rich.console import Console
    from rich.text import Text
    epix_msg = fr'''
|||  ______       _      _   _      _   
||| |  ____|     (_)    | \ | |    | |  
||| | |__   _ __  ___  _|  \| | ___| |_ 
||| |  __| | '_ \| \ \/ / . ` |/ _ \ __|
||| | |____| |_) | |>  <| |\  |  __/ |_ 
||| |______| .__/|_/_/\_\_| \_|\___|\__|
|||        | |                          
|||        |_|                          
|||
|||  v{version}
'''
    lns = epix_msg.split('\n')
    console = Console()
    for l in lns:
        txt = Text(l)
        txt.stylize('bold')
        for i in range(len(l)):
            txt.stylize(grad(i), i, i+1)
        console.print(txt)
