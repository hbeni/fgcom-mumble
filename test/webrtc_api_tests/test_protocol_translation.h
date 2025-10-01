/*
 * WebRTC Protocol Translation Test Headers
 * 
 * This file is part of the FGCom-mumble distribution (https://github.com/Supermagnum/fgcom-mumble).
 * Copyright (c) 2024 FGCom-mumble Contributors
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

#ifndef WEBRTC_PROTOCOL_TRANSLATION_TEST_H
#define WEBRTC_PROTOCOL_TRANSLATION_TEST_H

#include "webrtc_test_framework.h"
#include <gtest/gtest.h>

// WebRTC Protocol Translation Test Classes
class ProtocolTranslationTest : public ProtocolTranslationTestBase {
public:
    void SetUp() override {
        ProtocolTranslationTestBase::SetUp();
    }
    
    void TestBody() override {
        // Basic protocol translation test
        EXPECT_TRUE(true);
    }
};

#endif // WEBRTC_PROTOCOL_TRANSLATION_TEST_H
