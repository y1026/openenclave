# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(SampleAppHost CallWrappers.cpp SampleAppHost.cpp)
target_link_libraries(SampleAppHost oehostapp)
