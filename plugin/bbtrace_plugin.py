import os
import idaapi
import idautils
import idc
import traceback
from bbtrace.InfoParser import InfoParser
from bbtrace.Display import Display


PLUGIN_VERSION = "0.0.1"
AUTHORS        = "Fadhil Mandaga"
DATE           = "2018"

# Stunned panda face icon data.
ICON_DATA = "".join([
        "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1F\xF3\xFF\x61\x00\x00\x02\xCA\x49\x44\x41\x54\x78\x5E\x65",
        "\x53\x6D\x48\x53\x6F\x14\x3F\xBA\xB5\xB7\xA0\x8D\x20\x41\xF2\xBA\x5D\xB6\x0F\x56\xF4\x41\xA2\xC0\x9C\xE9\xB4\x29\x4A\x7D\xB0\x22\x7A\x11\x02\x23\x48\x2A\xD4\x74\x53\x33\x3F\xD4",
        "\x3E\x4A\x50\x19\xE4\xB0\xD0\x22\xCD\x44\x45\x4A\x31\x8C\x92\xA2\x3E\x65\x0A\x4D\xCB\x96\x7E\xE8\xD5\x97\xCC\xFE\xFE\x37\xA7\x77\xDB\xBD\xA7\xE7\x3C\xBE\x05\x9E\xED\xB7\xB3\xF3",
        "\x7B\x39\xF7\xEE\x19\x17\xA8\xAC\x56\xDB\x54\x82\x60\x41\xB3\x59\xBC\xFF\xAC\xF9\xCA\xB5\xAE\x86\xCA\xF9\x4E\xAF\x1B\x3B\xEA\x5D\x48\x9D\x66\xE2\x49\x27\x9F\xD5\x66\x9B\xA2\x1C",
        "\x22\x02\xD0\x40\xE4\x81\x6C\x3B\x76\x37\x56\xE3\x37\x5F\x2F\x62\xE8\x0B\xD3\x66\x19\x7E\x53\xA7\x99\x78\xAE\x1F\x64\x3E\x21\x71\x69\x09\x5F\x20\x98\x2D\x58\x70\x24\x07\x07\x7B",
        "\x6F\xB0\x79\x82\x61\x81\x21\xCC\xDE\x21\x54\x16\x02\xD4\x69\x26\x9E\x74\xEE\xCB\xCF\x4D\xC7\x44\xB3\x88\x7C\x81\xC5\x22\xFE\x6C\xB9\xE9\x46\x67\x46\x1A\x8A\x16\x2B\x0A\x5B\x05",
        "\x74\x66\x65\xE1\x98\x6F\x00\x31\x32\x87\x9F\x59\x77\x66\x66\x61\x42\xBC\xC0\xF5\x6C\x47\x1A\x36\xD7\xB9\x51\x14\xC5\x1E\xBE\xA0\xC3\x5B\xD9\x98\x99\xE1\xC0\xCE\xBE\x57\x48\xD7",
        "\x9A\x63\x68\xEA\x7C\x8A\xF6\x14\x3B\x9F\xF6\xA6\xA4\x60\xEB\xE3\x3E\x9C\x5F\xD6\x5A\x7A\xFA\x71\xBF\xC3\x81\x3D\x4D\x35\x0D\x7C\xC1\xF3\x87\x57\x43\xF9\x87\x8F\x21\x95\x5E\xAB",
        "\x41\x83\x4E\x83\x54\xDB\x92\x76\x20\xCA\xBF\xD0\x99\x9D\xBB\x4E\xDB\xBD\xC7\x8E\x2F\x5A\x3D\x74\x3D\x50\x03\x80\x7E\x7A\x7A\x06\x46\x47\xFD\xA0\x33\x6C\x84\x18\x46\x0C\xBD\x1F",
        "\x86\x2D\x71\x71\x00\x52\x10\x16\x17\xE6\xC1\xE7\x1B\x61\x9A\x81\x69\x31\x30\xFC\x61\x14\xB4\x3A\x3D\x20\x82\x1E\x58\xA9\x15\x05\x41\x14\x05\xB8\x58\xEE\x82\x7D\xE9\x99\x20\xCB",
        "\x32\x94\x95\x95\xC3\xA5\xD2\x53\x00\x51\x09\xAA\x4B\x0B\xA1\xB8\xA4\x0C\x52\x53\x33\x40\xA5\x52\x81\xDB\x5D\x01\xA2\x45\x00\x45\x51\x80\x2A\x36\x12\x8D\x42\x49\x51\x01\x44\xE5",
        "\x18\x90\x22\x0A\x98\x8C\x46\xF0\x54\x14\x42\x6D\x7D\x3B\xE4\x1C\x75\x41\xAD\xB7\x1D\x3C\x55\x85\x60\x32\x19\x41\x8A\x2A\xDC\x57\x5C\x74\x12\x28\x47\xA5\x8E\x44\xE4\xF0\x76\x5B",
        "\x82\xA6\xCD\x5B\x0D\xB2\x12\xE6\xE4\x06\xB5\x1A\x66\xA7\x26\x41\x92\xC2\xA0\xD5\x6A\x60\x67\x92\x19\xAE\x7B\xCE\x70\x4D\x15\xAB\x01\xAD\xC1\x08\x3F\x46\x64\x6E\x8E\x9D\xF9\x13",
        "\xE8\x1A\xFF\xE4\x63\x8A\x0E\xE6\x02\x41\xF8\x3F\x18\x82\x40\x28\x04\xFD\xDD\x75\xF0\xB6\xFF\x2E\x75\x9A\x89\x27\x9D\xFB\xC8\x4F\x39\xBE\xE0\xB4\xAB\xCE\x35\xFE\x71\x00\x16\x17",
        "\x25\x76\x50\x26\x76\x6B\x61\x86\x08\xE4\x1D\xAF\x81\xBC\x13\x97\xA9\xD3\x4C\x3C\xE9\xDC\x47\x7E\xCA\xF1\x05\x0C\x5F\x7D\xFE\xEF\x35\x03\xAF\x9F\x00\xB0\x73\x30\x9A\xE2\x81\x0E",
        "\xF6\xC1\xED\x52\xB8\x77\xAB\x98\x3A\xCD\xC4\x73\x9D\x7C\x6F\xDE\xF9\xCF\x53\x0E\xFE\xA9\xCD\xAE\xB3\x87\xCE\x75\x35\x54\xE1\xD0\xCB\x47\x38\x39\x36\x88\xFF\x4D\xF8\x57\x41\x33",
        "\xF1\xA4\x93\x0F\x00\x36\xAD\x3E\x4C\x6B\xC5\xC9\x5D\x77\x6A\x2F\xB4\x31\xA3\xC4\x40\x4F\x21\x0F\xD1\x4C\x3C\xE9\x2B\xE1\xF5\x0B\xD6\x90\xC8\x90\x4C\xE6\x35\xD0\xCC\x79\x5E\xFF",
        "\x2E\xF8\x0B\x2F\x3D\xE5\xC3\x97\x06\xCF\xCF\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82"])
ACT_ICON = idaapi.load_custom_icon(data=ICON_DATA, format="png")



def lex_citem_indexes(line):
    """
    Lex all ctree item indexes from a given line of text.
    -----------------------------------------------------------------------
    The HexRays decompiler output contains invisible text tokens that can
    be used to attribute spans of text to the ctree items that produced them.
    This function will simply scrape and return a list of all the these
    tokens (COLOR_ADDR) which contain item indexes into the ctree.

    https://github.com/gaasedelen/lighthouse/blob/006c46b4724f6f2cb7b36bc3ec6a45fbb49da6b9/plugin/lighthouse/util/ida.py#L131
    """
    i = 0
    indexes = []
    line_length = len(line)

    # lex COLOR_ADDR tokens from the line of text
    while i < line_length:

        # does this character mark the start of a new COLOR_* token?
        if line[i] == idaapi.COLOR_ON:

            # yes, so move past the COLOR_ON byte
            i += 1

            # is this sequence for a COLOR_ADDR?
            if ord(line[i]) == idaapi.COLOR_ADDR:

                # yes, so move past the COLOR_ADDR byte
                i += 1

                #
                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that represents an address/pointer.
                # in this context, it is actually the index number of a citem
                #

                citem_index = int(line[i:i+idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE

                # save the extracted citem index
                indexes.append(citem_index)

                # skip to the next iteration as i has moved
                continue

        # nothing we care about happened, keep lexing forward
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes


class IDACtxEntry(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS


class BBTrace(idaapi.plugin_t):
    """
    The BBTrace IDA Plugin.
    """

    flags = 0
    comment = 'BBTrace'
    help = 'BBTrace'
    wanted_name = 'BBTrace'
    wanted_hotkey = 'Alt+F10'

    ACTION_LOAD_FILE         = "bbtrace:load_file"

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
                self.ACTION_LOAD_FILE,  # Name. Acts as an ID. Must be unique.
                "BbTrace Flow File...",          # Label. That's what users see.
                IDACtxEntry(self.interactive_load_file), # Handler. Called when activated, and for updating
                None,         # Shortcut (optional)
                "Load bbtrace flow file...",  # Tooltip (optional)
                ACT_ICON)         # Icon ID (optional)

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register load_file action with IDA")

        # attach the action to the File-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "File/Load file/",       # Relative path of where to add the action
            self.ACTION_LOAD_FILE,   # The action ID (see above)
            idaapi.SETMENU_APP       # We want to append the action after ^
        )
        if not result:
            RuntimeError("Failed action attach load_file")

        if idaapi.init_hexrays_plugin():
            idaapi.install_hexrays_callback(self.hexrays_event)
        else:
            print('hexrays is not available.')

        self.display = None

        print("BBTrace initialized.")
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        if not self.display:
            self.display = Display()
        self.display.Show("BbTrace Graph")

    def interactive_load_file(self):
        """
        Loading bbtrace.
        """

        print("Done BbTrace.")

    def hexrays_event(self, event, *args):
        try:
            # if event == idaapi.hxe_maturity:
            # cfunc, maturity = args
            # if maturity == idaapi.CMAT_FINAL:
            if event == idaapi.hxe_text_ready:
                # more code-friendly, readable aliases
                vdui = args[0]
                cfunc = vdui.cfunc

                self.paint_hexrays(cfunc)

        except:
            traceback.print_exc()

        return 0

    def paint_hexrays(self, cfunc):
        sv = cfunc.get_pseudocode()

        lines_painted = 0

        for sline in sv:
            indexes = lex_citem_indexes(sline.line)
            for index in indexes:
                try:
                    item = cfunc.treeitems[index]
                    ea = item.ea

                # apparently this is a thing on IDA 6.95
                except IndexError as e:
                    continue

                col = idc.get_color(ea, CIC_ITEM)
                if col != BADADDR:
                    sline.bgcolor = col
                    lines_painted += 1

        if not lines_painted:
            return

        col = 0xccffcc

        for line_number in xrange(0, cfunc.hdrlines):
            sv[line_number].bgcolor = col

        idaapi.refresh_idaview_anyway()


def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return BBTrace()

