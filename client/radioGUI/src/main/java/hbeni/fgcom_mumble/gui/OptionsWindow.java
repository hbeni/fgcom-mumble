/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package hbeni.fgcom_mumble.gui;

import hbeni.fgcom_mumble.radioGUI;
import java.net.URL;
import javax.swing.ImageIcon;

/**
 *
 * @author beni
 */
public class OptionsWindow extends javax.swing.JFrame {

    /**
     * Creates new form OptionsWindow
     */
    public OptionsWindow() {
        initComponents();
        
        URL iconURL = getClass().getResource("/fgcom_logo.png");
        ImageIcon icon = new ImageIcon(iconURL);
        this.setIconImage(icon.getImage());
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel2 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jTextField_udpPort = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jCheckBox_EnableAudioEffects = new javax.swing.JCheckBox();
        jLabel10 = new javax.swing.JLabel();
        jCheckBox_HearAllUsers = new javax.swing.JCheckBox();
        jLabel11 = new javax.swing.JLabel();
        jTextField_udpHost = new javax.swing.JTextField();
        jLabel12 = new javax.swing.JLabel();
        jTextField_udpSendRateHz = new javax.swing.JTextField();
        filler1 = new javax.swing.Box.Filler(new java.awt.Dimension(0, 12), new java.awt.Dimension(0, 12), new java.awt.Dimension(32767, 12));
        jButton_OK = new javax.swing.JButton();
        jButton_Cancel = new javax.swing.JButton();
        jPanel3 = new javax.swing.JPanel();
        jLabel13 = new javax.swing.JLabel();
        jSlider_qlysetting = new javax.swing.JSlider();
        jLabel_qlyvalue = new javax.swing.JLabel();
        jLabel14 = new javax.swing.JLabel();
        jLabel15 = new javax.swing.JLabel();
        jLabel16 = new javax.swing.JLabel();
        jLabel17 = new javax.swing.JLabel();
        jLabel18 = new javax.swing.JLabel();
        jLabel19 = new javax.swing.JLabel();
        jPanel4 = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jTextField_simConnectHost = new javax.swing.JTextField();
        jTextField_simConnectPort = new javax.swing.JTextField();

        setTitle("Options");
        addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentShown(java.awt.event.ComponentEvent evt) {
                formComponentShown(evt);
            }
        });

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder("Common Options"));
        jPanel2.setPreferredSize(new java.awt.Dimension(394, 250));

        jLabel1.setText("Plugin UDP Port");
        jLabel1.setToolTipText("Where Radio GUI sends its packets");

        jTextField_udpPort.setText("err");
        jTextField_udpPort.setToolTipText("Where Radio GUI sends its packets");
        jTextField_udpPort.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                jTextField_udpPortKeyReleased(evt);
            }
        });

        jLabel3.setText("Plugin UDP send rate (Hz)");
        jLabel3.setToolTipText("If enabled, you will hear static and degraded signal quality based on signal reception");

        jCheckBox_EnableAudioEffects.setToolTipText("If enabled, you will hear static and degraded signal quality based on signal reception");

        jLabel10.setText("Enable audio effects");
        jLabel10.setToolTipText("When enabled, you will hear mumble users that do not use the plugin");

        jCheckBox_HearAllUsers.setToolTipText("When enabled, you will hear mumble users that do not use the plugin");

        jLabel11.setText("Plugin UDP Host");
        jLabel11.setToolTipText("Where Radio GUI sends its packets");

        jTextField_udpHost.setText("err");
        jTextField_udpHost.setToolTipText("Where Radio GUI sends its packets");

        jLabel12.setText("Hear non-plugin users");
        jLabel12.setToolTipText("When enabled, you will hear mumble users that do not use the plugin");

        jTextField_udpSendRateHz.setText("err");
        jTextField_udpSendRateHz.setToolTipText("Where Radio GUI sends its packets");
        jTextField_udpSendRateHz.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                jTextField_udpSendRateHzKeyReleased(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1)
                            .addComponent(jLabel3)
                            .addComponent(jLabel10)
                            .addComponent(jLabel11)
                            .addComponent(jLabel12))
                        .addGap(44, 44, 44))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                        .addComponent(filler1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)))
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jTextField_udpHost)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jTextField_udpPort, javax.swing.GroupLayout.PREFERRED_SIZE, 103, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jCheckBox_EnableAudioEffects)
                            .addComponent(jTextField_udpSendRateHz, javax.swing.GroupLayout.PREFERRED_SIZE, 103, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jCheckBox_HearAllUsers))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel11)
                    .addComponent(jTextField_udpHost, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 18, Short.MAX_VALUE)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(jTextField_udpPort, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 18, Short.MAX_VALUE)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(jTextField_udpSendRateHz, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addComponent(jLabel10)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel12))
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addComponent(jCheckBox_EnableAudioEffects)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jCheckBox_HearAllUsers)))
                .addContainerGap())
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(filler1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        jButton_OK.setText("OK");
        jButton_OK.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_OKActionPerformed(evt);
            }
        });

        jButton_Cancel.setText("Cancel");
        jButton_Cancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton_CancelActionPerformed(evt);
            }
        });

        jPanel3.setBorder(javax.swing.BorderFactory.createTitledBorder("Debug Options"));

        jLabel13.setText("Override signal Quality:");
        jLabel13.setToolTipText("Received signals will always be of the given quality. Needs a debug build of the mumble plugin!");

        jSlider_qlysetting.setMajorTickSpacing(25);
        jSlider_qlysetting.setMinimum(-1);
        jSlider_qlysetting.setMinorTickSpacing(5);
        jSlider_qlysetting.setPaintTicks(true);
        jSlider_qlysetting.setToolTipText("Received signals will always be of the given quality. Needs a debug build of the mumble plugin!");
        jSlider_qlysetting.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                jSlider_qlysettingStateChanged(evt);
            }
        });

        jLabel_qlyvalue.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        jLabel_qlyvalue.setText("err");

        jLabel14.setFont(jLabel14.getFont().deriveFont(jLabel14.getFont().getSize()-4f));
        jLabel14.setText("(needs a plugin debug build!)");
        jLabel14.setToolTipText("Received signals will always be of the given quality. Needs a debug build of the mumble plugin!");

        jLabel15.setFont(jLabel15.getFont().deriveFont(jLabel15.getFont().getSize()-4f));
        jLabel15.setText("off");
        jLabel15.setToolTipText("Received signals will always be of the given quality. Needs a debug build of the mumble plugin!");

        jLabel16.setFont(jLabel16.getFont().deriveFont(jLabel16.getFont().getSize()-4f));
        jLabel16.setText("25%");
        jLabel16.setToolTipText("Received signals will always be of the given quality. Needs a debug build of the mumble plugin!");

        jLabel17.setFont(jLabel17.getFont().deriveFont(jLabel17.getFont().getSize()-4f));
        jLabel17.setText("50%");
        jLabel17.setToolTipText("Received signals will always be of the given quality. Needs a debug build of the mumble plugin!");

        jLabel18.setFont(jLabel18.getFont().deriveFont(jLabel18.getFont().getSize()-4f));
        jLabel18.setText("75%");
        jLabel18.setToolTipText("Received signals will always be of the given quality. Needs a debug build of the mumble plugin!");

        jLabel19.setFont(jLabel19.getFont().deriveFont(jLabel19.getFont().getSize()-4f));
        jLabel19.setText("100%");
        jLabel19.setToolTipText("Received signals will always be of the given quality. Needs a debug build of the mumble plugin!");

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addComponent(jLabel13)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel_qlyvalue, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addComponent(jLabel14)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addComponent(jLabel15)
                        .addGap(47, 47, 47)
                        .addComponent(jLabel16)
                        .addGap(34, 34, 34)
                        .addComponent(jLabel17)
                        .addGap(40, 40, 40)
                        .addComponent(jLabel18)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jLabel19))
                    .addComponent(jSlider_qlysetting, javax.swing.GroupLayout.PREFERRED_SIZE, 239, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel13)
                            .addComponent(jLabel_qlyvalue))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel14))
                    .addComponent(jSlider_qlysetting, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel15)
                    .addComponent(jLabel16)
                    .addComponent(jLabel17)
                    .addComponent(jLabel18)
                    .addComponent(jLabel19))
                .addContainerGap(22, Short.MAX_VALUE))
        );

        jPanel4.setBorder(javax.swing.BorderFactory.createTitledBorder("SimConnect Options"));

        jLabel2.setText("Host");

        jLabel4.setText("Default Port");
        jLabel4.setToolTipText("The port to be used if auto-guessing fails");

        jTextField_simConnectHost.setText("err");

        jTextField_simConnectPort.setText("err");
        jTextField_simConnectPort.setToolTipText("<html>The port to be used if auto-guessing fails.<br/>\nTry the following:\n<table>\n<tr> <td>500</td><td>MSFS 2020</td> </tr>\n<tr> <td>7421</td><td>FSX?</td> </tr>\n</table>\n</html>");
        jTextField_simConnectPort.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                jTextField_simConnectPortKeyReleased(evt);
            }
        });

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel2)
                    .addComponent(jLabel4))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jTextField_simConnectHost, javax.swing.GroupLayout.PREFERRED_SIZE, 219, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTextField_simConnectPort, javax.swing.GroupLayout.PREFERRED_SIZE, 103, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(jTextField_simConnectHost, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4)
                    .addComponent(jTextField_simConnectPort, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jPanel4, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 479, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(jButton_Cancel, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(12, 12, 12)
                        .addComponent(jButton_OK, javax.swing.GroupLayout.PREFERRED_SIZE, 80, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jPanel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, 183, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton_Cancel)
                    .addComponent(jButton_OK))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    public void prepareSimConnect() {
        jTextField_simConnectHost.setEnabled(false);
        jTextField_simConnectPort.setEnabled(false);
        this.repaint();
    }
        
    
    private void jButton_OKActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_OKActionPerformed
        // Save settings
        radioGUI.Options.udpHost = jTextField_udpHost.getText();
        radioGUI.Options.udpPort = Integer.parseInt(jTextField_udpPort.getText());
        radioGUI.Options.udpSendRateHz = Float.parseFloat(jTextField_udpSendRateHz.getText());
        radioGUI.Options.enableAudioEffecs = jCheckBox_EnableAudioEffects.isSelected();
        radioGUI.Options.simConnectHost = jTextField_simConnectHost.getText();
        radioGUI.Options.simConnectPort = Integer.parseInt(jTextField_simConnectPort.getText());
        radioGUI.Options.allowHearingNonPluginUsers = jCheckBox_HearAllUsers.isSelected();
        radioGUI.Options.debugSignalOverride = jSlider_qlysetting.getValue();
        
        this.setVisible(false);
    }//GEN-LAST:event_jButton_OKActionPerformed

    /* called on showing of the frame */
    private void formComponentShown(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_formComponentShown
        String tgt;
        if (radioGUI.Options.debugSignalOverride >= 0.0) {
            tgt =  Integer.toString(radioGUI.Options.debugSignalOverride)+"%";
        } else {
            tgt = new String("off");
        }
        jLabel_qlyvalue.setText(tgt);
        jSlider_qlysetting.setValue(radioGUI.Options.debugSignalOverride);
        
        jTextField_udpHost.setText(radioGUI.Options.udpHost);
        jTextField_udpPort.setText(Integer.toString(radioGUI.Options.udpPort));
        jTextField_udpSendRateHz.setText(Float.toString(radioGUI.Options.udpSendRateHz));
        jCheckBox_EnableAudioEffects.setSelected(radioGUI.Options.enableAudioEffecs);
        
        jTextField_simConnectHost.setText(radioGUI.Options.simConnectHost);
        jTextField_simConnectPort.setText(Integer.toString(radioGUI.Options.simConnectPort));
        
        jCheckBox_EnableAudioEffects.setSelected(radioGUI.Options.enableAudioEffecs);
        jCheckBox_HearAllUsers.setSelected(radioGUI.Options.allowHearingNonPluginUsers);
    }//GEN-LAST:event_formComponentShown

    private void jButton_CancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton_CancelActionPerformed
        this.setVisible(false);
    }//GEN-LAST:event_jButton_CancelActionPerformed

    private void jTextField_udpSendRateHzKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_jTextField_udpSendRateHzKeyReleased
        // sanitize input
        try {
            if (Float.parseFloat(jTextField_udpSendRateHz.getText()) > 25) {
                jTextField_udpSendRateHz.setText("25.0");
                jTextField_udpSendRateHz.repaint();
            }
            if (Float.parseFloat(jTextField_udpSendRateHz.getText()) < 0.1) {
                jTextField_udpSendRateHz.setText("0.1");
                jTextField_udpSendRateHz.repaint();
            }
        } catch (NumberFormatException e) {
            jTextField_udpSendRateHz.setText(Float.toString(radioGUI.Options.udpSendRateHz));
        }
    }//GEN-LAST:event_jTextField_udpSendRateHzKeyReleased

    private void jTextField_udpPortKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_jTextField_udpPortKeyReleased
        // sanitize input
        try {
            Integer.parseInt(jTextField_udpPort.getText());
        } catch (NumberFormatException e) {
            jTextField_udpPort.setText(Integer.toString(radioGUI.Options.udpPort));
        }
    }//GEN-LAST:event_jTextField_udpPortKeyReleased

    private void jSlider_qlysettingStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_jSlider_qlysettingStateChanged
        // TODO add your handling code here:
    }//GEN-LAST:event_jSlider_qlysettingStateChanged

    private void jTextField_simConnectPortKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_jTextField_simConnectPortKeyReleased
        // sanitize input
        try {
            Integer.parseInt(jTextField_simConnectPort.getText());
        } catch (NumberFormatException e) {
            jTextField_simConnectPort.setText(Integer.toString(radioGUI.Options.simConnectPort));
        }
    }//GEN-LAST:event_jTextField_simConnectPortKeyReleased


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.Box.Filler filler1;
    private javax.swing.JButton jButton_Cancel;
    private javax.swing.JButton jButton_OK;
    private javax.swing.JCheckBox jCheckBox_EnableAudioEffects;
    private javax.swing.JCheckBox jCheckBox_HearAllUsers;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel16;
    private javax.swing.JLabel jLabel17;
    private javax.swing.JLabel jLabel18;
    private javax.swing.JLabel jLabel19;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel_qlyvalue;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JSlider jSlider_qlysetting;
    private javax.swing.JTextField jTextField_simConnectHost;
    private javax.swing.JTextField jTextField_simConnectPort;
    private javax.swing.JTextField jTextField_udpHost;
    private javax.swing.JTextField jTextField_udpPort;
    private javax.swing.JTextField jTextField_udpSendRateHz;
    // End of variables declaration//GEN-END:variables
}
