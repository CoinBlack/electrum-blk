import os

from pythonforandroid.recipes.Pillow import PillowRecipe
from pythonforandroid.util import HashPinnedDependency, load_source

util = load_source('util', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'util.py'))


assert PillowRecipe._version == "11.3.0"
assert PillowRecipe.depends == ['png', 'jpeg', 'freetype', 'python3'], PillowRecipe.depends
assert PillowRecipe.python_depends == []


class PillowRecipePinned(util.InheritedRecipeMixin, PillowRecipe):
    sha512sum = "7d97e623bd41da94dd89a66dc600cea016d0a4f33fbf036175768ea96b2031c1968acf4fc3d9b2835ce93f9533838a9ce68a6579a7397f4aeccafb6032adb3db"
    hostpython_prerequisites = [
        HashPinnedDependency(package="setuptools==80.9.0",
                             hashes=['sha256:062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922']),
    ]


recipe = PillowRecipePinned()