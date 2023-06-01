#
# FGCom-mumble ComBar
#
# A small canvas GUI showing PTT buttons for the registered COM radios.
# This is helpful for aircraft with more than two COM radios (like airliners),
# because the default legacy fgcom keybindings just address COM1 and COM2.
#
# @author Benedikt Hallinger, 2021


# Overload canvas button class to make it spring loaded
# see https://forum.flightgear.org/viewtopic.php?p=323662&sid=e417bcd6337e277f9f975244acb358db#p323662
canvas.gui.widgets.SpringButton = canvas.gui.widgets.Button;
canvas.gui.widgets.SpringButton.setDown = func(down = 1)
{
    if( me._checkable or me._down == down )
        return me;

    me._down = down;
    me._onStateChange();

    if (!me._down){
        me._trigger("mouse_up", {checked: 0});
        #print ("mouse up");
    }
    else{
        me._trigger("mouse_down", {checked: 0});
        #print ("mouse down");
    }

    return me;
};


var combar = {

    comPTTButton_size: [65,25],
    dialogOpened: 0,
    show: func() {
        if (me.dialogOpened == 1) return; # allow just one dialog instance
        
        print("Addon FGCom-mumble: combar initializing");
        dlgWindow = canvas.Window.new([975, 25], "dialog")
                        .setTitle("FGCom-mumble COMBar");

        dlgWindow.del = func() {
            print("Addon FGCom-mumble: combar closed");
            combar.dialogOpened = 0;

            call(canvas.Window.del, [], me);
        };

        dlgCanvas = dlgWindow.createCanvas().set("background", canvas.style.getColor("bg_color"));
        dlgCanvas.setColorBackground(0.5, 0.5, 0.5, 0.0);

        var root = dlgCanvas.createGroup();

        var myLayout = canvas.HBoxLayout.new();
        dlgCanvas.setLayout(myLayout);


        # Generate PTT buttons for the configured radios
        foreach (var ridx; sort(keys(FGComMumble_radios.COM_radios), func(a,b) {return a<b?-1:1;})) {
            var r = FGComMumble_radios.COM_radios[ridx];
            if (!r.is_used) {
                print("Addon FGCom-mumble: combar skipping "~r.root.getPath());
                continue;
            }

            print("Addon FGCom-mumble: combar adding "~r.root.getPath()~" (COM"~r.fgcomPacketStr.getIndex()~")");

            var newSizeWidth = math.round((ridx)*me.comPTTButton_size[0] + me.comPTTButton_size[0]/4);
            dlgWindow.setSize([newSizeWidth, me.comPTTButton_size[1]+4]);

            var button = canvas.gui.widgets.SpringButton.new(root, canvas.style, {})
                    .setText("COM" ~ r.fgcomPacketStr.getIndex())
                    .setFixedSize(me.comPTTButton_size[0], me.comPTTButton_size[1]);
            var init_button = func(b,rp,ci) {
                b.ptt_prop = rp~"/ptt";
                b.listen("mouse_down", func(e) {
                    print("Addon FGCom-mumble: pushing COM"~ci~" "~b.ptt_prop);
                    setprop(b.ptt_prop, 1);
                });
                b.listen("mouse_up", func(e) {
                    print("Addon FGCom-mumble: releasing COM"~ci~" "~b.ptt_prop);
                    setprop(b.ptt_prop, 0);
                });

                var update_button_timer = maketimer(1, func() {
                    var radio_operable = getprop(rp~"/operable");
                    if (radio_operable) {
                        b.setEnabled(1);
                    } else {
                        b.setEnabled(0);
                    }
                });
                update_button_timer.start();
            };
            init_button(button, r.root.getPath(), r.fgcomPacketStr.getIndex());

            myLayout.addItem(button);
        }

        me.dialogOpened = 1;

    }
};
