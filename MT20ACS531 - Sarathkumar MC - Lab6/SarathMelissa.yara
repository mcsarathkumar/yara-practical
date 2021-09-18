rule MicrosoftMelissa
{
    meta:
        description = "MicrosoftMelissa is a virus that speads over outlook"
        os = "mswindows"
        filetype = "Macro"
        maltype = "Virus"

    strings:
        $melissa0 = "Important Message From"
        $melissa1 = "Here is that document you asked for ... don't show anyone else ;-)"
        $melissa2 = "WORD/Melissa written by Kwyjibo"
        $melissa3 = "Works in both Word 2000 and Word 97"
        $melissa4 = "Worm? Macro Virus? Word 97 Virus? Word 2000 Virus? You Decide!"
        $melissa5 = "Word -> Email | Word 97 <--> Word 2000 ... it's a new age!"
    
    condition:
        all of ($melissa*)
}
