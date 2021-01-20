# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest

from psrp.dotnet.complex_types import (
    ApartmentState,
    ConsoleColor,
    Coordinates,
    ErrorCategory,
    ErrorCategoryInfo,
    ErrorRecord,
    HostDefaultData,
    HostInfo,
    InformationalRecord,
    NETException,
    ProgressRecordType,
    PSInvocationState,
    PSThreadOptions,
    RemoteStreamOptions,
    RunspacePoolState,
    Size,
)

from psrp.dotnet.primitive_types import (
    PSInt,
    PSSecureString,
    PSString,
)

from psrp.dotnet.psrp_messages import (
    InformationRecord,
    ProgressRecord,
)

from psrp.exceptions import (
    MissingCipherError,
    RunspacePoolWantRead,
)

from psrp.protocol.powershell import (
    ClientPowerShell,
    RunspacePool,
    ServerPowerShell,
    ServerRunspacePool,
    StreamType,
)

from psrp.protocol.powershell_events import (
    ApplicationPrivateDataEvent,
    CreatePipelineEvent,
    DebugRecordEvent,
    EncryptedSessionKeyEvent,
    EndOfPipelineInputEvent,
    ErrorRecordEvent,
    InformationRecordEvent,
    InitRunspacePoolEvent,
    PipelineInputEvent,
    PipelineOutputEvent,
    PipelineStateEvent,
    ProgressRecordEvent,
    PublicKeyEvent,
    PublicKeyRequestEvent,
    RunspacePoolStateEvent,
    SessionCapabilityEvent,
    VerboseRecordEvent,
    WarningRecordEvent,
)


def get_runspace_pair():
    client = RunspacePool()
    server = ServerRunspacePool()

    client.open()
    server.receive_data(client.data_to_send())
    server.next_event()
    server.next_event()
    client.receive_data(server.data_to_send())
    client.next_event()
    client.next_event()
    client.next_event()
    
    return client, server


def test_open_runspacepool():
    client = RunspacePool()
    server = ServerRunspacePool()
    assert client.state == RunspacePoolState.BeforeOpen
    assert server.state == RunspacePoolState.BeforeOpen

    client.open()
    assert client.state == RunspacePoolState.Opening

    first = client.data_to_send()
    assert len(first.data) > 0
    assert first.stream_type == StreamType.default
    assert first.pipeline_id is None
    assert client.state == RunspacePoolState.NegotiationSent

    assert client.data_to_send() is None

    server.receive_data(first)
    session_cap = server.next_event()
    assert isinstance(session_cap, SessionCapabilityEvent)
    assert session_cap.ps_object.PSVersion == server.their_capability.PSVersion
    assert session_cap.ps_object.SerializationVersion == server.their_capability.SerializationVersion
    assert session_cap.ps_object.protocolversion == server.their_capability.protocolversion
    assert client.state == RunspacePoolState.NegotiationSent
    assert server.state == RunspacePoolState.NegotiationSucceeded
    assert server.runspace_id == client.runspace_id

    second = server.data_to_send()
    assert len(second.data) > 0
    assert second.stream_type == StreamType.default
    assert second.pipeline_id is None

    client.receive_data(second)
    session_cap = client.next_event()
    assert isinstance(session_cap, SessionCapabilityEvent)
    assert session_cap.ps_object.PSVersion == client.their_capability.PSVersion
    assert session_cap.ps_object.SerializationVersion == client.their_capability.SerializationVersion
    assert session_cap.ps_object.protocolversion == client.their_capability.protocolversion
    assert client.state == RunspacePoolState.NegotiationSucceeded
    assert server.state == RunspacePoolState.NegotiationSucceeded

    init_runspace_pool = server.next_event()
    assert isinstance(init_runspace_pool, InitRunspacePoolEvent)
    assert init_runspace_pool.ps_object.ApartmentState == ApartmentState.Unknown
    assert init_runspace_pool.ps_object.ApplicationArguments == {}
    assert init_runspace_pool.ps_object.HostInfo._isHostNull
    assert init_runspace_pool.ps_object.HostInfo._isHostRawUINull
    assert init_runspace_pool.ps_object.HostInfo._isHostUINull
    assert init_runspace_pool.ps_object.HostInfo._useRunspaceHost
    assert init_runspace_pool.ps_object.MaxRunspaces == 1
    assert init_runspace_pool.ps_object.MinRunspaces == 1
    assert init_runspace_pool.ps_object.PSThreadOptions == PSThreadOptions.Default
    assert client.state == RunspacePoolState.NegotiationSucceeded
    assert server.state == RunspacePoolState.Opened

    with pytest.raises(RunspacePoolWantRead):
        server.next_event()

    third = server.data_to_send()
    assert len(third.data) > 0
    assert third.stream_type == StreamType.default
    assert third.pipeline_id is None

    assert server.data_to_send() is None

    client.receive_data(third)
    private_data = client.next_event()
    assert isinstance(private_data, ApplicationPrivateDataEvent)
    assert private_data.ps_object.ApplicationPrivateData == {}
    assert client.application_private_data == {}
    assert client.state == RunspacePoolState.NegotiationSucceeded
    assert server.state == RunspacePoolState.Opened

    runspace_state = client.next_event()
    assert isinstance(runspace_state, RunspacePoolStateEvent)
    assert client.state == RunspacePoolState.Opened
    assert server.state == RunspacePoolState.Opened

    with pytest.raises(RunspacePoolWantRead):
        client.next_event()

    assert client.data_to_send() is None


def test_open_runspacepool_small():
    client = RunspacePool()
    server = ServerRunspacePool()
    assert client.state == RunspacePoolState.BeforeOpen
    assert server.state == RunspacePoolState.BeforeOpen

    client.open()
    assert client.state == RunspacePoolState.Opening
    assert server.state == RunspacePoolState.BeforeOpen

    first = client.data_to_send(60)
    assert len(first.data) == 60
    assert first.stream_type == StreamType.default
    assert first.pipeline_id is None

    server.receive_data(first)
    with pytest.raises(RunspacePoolWantRead):
        server.next_event()
    assert client.state == RunspacePoolState.Opening
    assert server.state == RunspacePoolState.BeforeOpen

    server.receive_data(client.data_to_send(60))
    with pytest.raises(RunspacePoolWantRead):
        server.next_event()
    assert client.state == RunspacePoolState.Opening
    assert server.state == RunspacePoolState.BeforeOpen

    server.receive_data(client.data_to_send(60))
    with pytest.raises(RunspacePoolWantRead):
        server.next_event()
    assert client.state == RunspacePoolState.Opening
    assert server.state == RunspacePoolState.BeforeOpen

    server.receive_data(client.data_to_send(60))
    with pytest.raises(RunspacePoolWantRead):
        server.next_event()
    assert client.state == RunspacePoolState.Opening
    assert server.state == RunspacePoolState.BeforeOpen

    server.receive_data(client.data_to_send(60))
    with pytest.raises(RunspacePoolWantRead):
        server.next_event()
    assert client.state == RunspacePoolState.Opening
    assert server.state == RunspacePoolState.BeforeOpen

    server.receive_data(client.data_to_send(60))
    session_cap = server.next_event()
    assert isinstance(session_cap, SessionCapabilityEvent)
    assert client.state == RunspacePoolState.NegotiationSent
    assert server.state == RunspacePoolState.NegotiationSucceeded
    with pytest.raises(RunspacePoolWantRead):
        server.next_event()

    client.receive_data(server.data_to_send())
    assert server.data_to_send() is None
    session_cap = client.next_event()
    assert isinstance(session_cap, SessionCapabilityEvent)
    assert client.state == RunspacePoolState.NegotiationSucceeded
    assert server.state == RunspacePoolState.NegotiationSucceeded
    with pytest.raises(RunspacePoolWantRead):
        client.next_event()

    server.receive_data(client.data_to_send())
    init_runspace = server.next_event()
    assert isinstance(init_runspace, InitRunspacePoolEvent)
    assert client.state == RunspacePoolState.NegotiationSucceeded
    assert server.state == RunspacePoolState.Opened

    client.receive_data(server.data_to_send())
    assert server.data_to_send() is None
    private_data = client.next_event()
    assert isinstance(private_data, ApplicationPrivateDataEvent)
    assert client.state == RunspacePoolState.NegotiationSucceeded
    assert server.state == RunspacePoolState.Opened

    runspace_state = client.next_event()
    assert isinstance(runspace_state, RunspacePoolStateEvent)
    assert client.state == RunspacePoolState.Opened
    assert server.state == RunspacePoolState.Opened

    with pytest.raises(RunspacePoolWantRead):
        client.next_event()


def test_create_pipeline():
    client, server = get_runspace_pair()

    c_pipeline = ClientPowerShell(client)
    assert c_pipeline.state == PSInvocationState.NotStarted
    
    c_pipeline.add_script('testing')
    c_pipeline.invoke()
    assert c_pipeline.state == PSInvocationState.Running

    c_command = client.data_to_send()
    server.receive_data(c_command)
    create_pipeline = server.next_event(c_command.pipeline_id)
    s_pipeline = create_pipeline.pipeline
    assert isinstance(create_pipeline, CreatePipelineEvent)
    assert isinstance(s_pipeline, ServerPowerShell)
    assert s_pipeline.add_to_history is False
    assert s_pipeline.apartment_state == ApartmentState.Unknown
    assert len(s_pipeline.commands) == 1
    assert s_pipeline.commands[0].command_text == 'testing'
    assert s_pipeline.commands[0].end_of_statement is True
    assert s_pipeline.commands[0].is_script is True
    assert s_pipeline.commands[0].parameters == []
    assert s_pipeline.commands[0].use_local_scope is None
    assert s_pipeline.history is None
    assert isinstance(s_pipeline.host, HostInfo)
    assert s_pipeline.host.host_default_data is None
    assert s_pipeline.host.is_host_null is True
    assert s_pipeline.host.is_host_raw_ui_null is True
    assert s_pipeline.host.is_host_ui_null is True
    assert s_pipeline.host.use_runspace_host is True
    assert s_pipeline.is_nested is False
    assert s_pipeline.no_input is True
    assert s_pipeline.pipeline_id == c_pipeline.pipeline_id
    assert s_pipeline.redirect_shell_error_to_out is True
    assert s_pipeline.remote_stream_options == RemoteStreamOptions.none
    assert s_pipeline.runspace_pool == server
    assert s_pipeline.state == PSInvocationState.NotStarted
    assert len(server.pipeline_table) == 1
    assert server.pipeline_table[s_pipeline.pipeline_id] == s_pipeline

    s_pipeline.state = PSInvocationState.Running
    s_pipeline.write_output('output msg')
    s_pipeline.close()
    client.receive_data(server.data_to_send())
    out = client.next_event(c_pipeline.pipeline_id)
    assert server.pipeline_table == {}
    assert isinstance(out, PipelineOutputEvent)
    assert out.ps_object == 'output msg'
    
    state = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(state, PipelineStateEvent)
    assert state.state == PSInvocationState.Completed
    assert c_pipeline.state == PSInvocationState.Completed
    assert client.pipeline_table == {}


def test_create_pipeline_host_data():
    client, server = get_runspace_pair()
    
    c_host_data = HostDefaultData(
        foreground_color=ConsoleColor.Red,
        background_color=ConsoleColor.White,
        cursor_position=Coordinates(1, 2),
        window_position=Coordinates(3, 4),
        cursor_size=5,
        buffer_size=Size(6, 7),
        window_size=Size(8, 9),
        max_window_size=Size(10, 11),
        max_physical_window_size=Size(12, 13),
        window_title='Test Title',
    )
    c_host = HostInfo(
        use_runspace_host=False,
        is_host_null=False,
        is_host_ui_null=False,
        is_host_raw_ui_null=False,
        host_default_data=c_host_data,
    )

    c_pipeline = ClientPowerShell(client, host=c_host)
    c_pipeline.add_script('testing')
    c_pipeline.invoke()
    
    server.receive_data(client.data_to_send())
    create_pipeline = server.next_event(c_pipeline.pipeline_id)
    s_pipeline = create_pipeline.pipeline
    s_host = s_pipeline.host
    
    assert isinstance(s_host, HostInfo)
    assert s_host.is_host_null is False
    assert s_host.is_host_ui_null is False
    assert s_host.is_host_raw_ui_null is False
    assert s_host.use_runspace_host is False
    assert isinstance(s_host.host_default_data, HostDefaultData)
    assert s_host.host_default_data.foreground_color == ConsoleColor.Red
    assert s_host.host_default_data.background_color == ConsoleColor.White
    assert s_host.host_default_data.cursor_position.X == 1
    assert s_host.host_default_data.cursor_position.Y == 2
    assert s_host.host_default_data.window_position.X == 3
    assert s_host.host_default_data.window_position.Y == 4
    assert s_host.host_default_data.cursor_size == 5
    assert s_host.host_default_data.buffer_size.Width == 6
    assert s_host.host_default_data.buffer_size.Height == 7
    assert s_host.host_default_data.window_size.Width == 8
    assert s_host.host_default_data.window_size.Height == 9
    assert s_host.host_default_data.max_window_size.Width == 10
    assert s_host.host_default_data.max_window_size.Height == 11
    assert s_host.host_default_data.max_physical_window_size.Width == 12
    assert s_host.host_default_data.max_physical_window_size.Height == 13
    assert s_host.host_default_data.window_title == 'Test Title'


def test_pipeline_input_output():
    client, server = get_runspace_pair()

    c_pipeline = ClientPowerShell(client, no_input=False)
    assert c_pipeline.state == PSInvocationState.NotStarted

    c_pipeline.add_script('Get-Service')
    c_pipeline.invoke()
    assert c_pipeline.state == PSInvocationState.Running

    c_command = client.data_to_send()
    server.receive_data(c_command)
    create_pipeline = server.next_event(c_command.pipeline_id)
    s_pipeline = create_pipeline.pipeline
    assert isinstance(create_pipeline, CreatePipelineEvent)
    assert isinstance(s_pipeline, ServerPowerShell)
    assert len(s_pipeline.commands) == 1
    assert s_pipeline.commands[0].command_text == 'Get-Service'
    assert s_pipeline.no_input is False
    assert s_pipeline.runspace_pool == server
    assert s_pipeline.state == PSInvocationState.NotStarted
    assert len(server.pipeline_table) == 1
    assert server.pipeline_table[s_pipeline.pipeline_id] == s_pipeline
    s_pipeline.state = PSInvocationState.Running

    c_pipeline.send('input 1')
    c_pipeline.send('input 2')
    c_pipeline.send(3)
    server.receive_data(client.data_to_send())
    
    input1 = server.next_event(c_command.pipeline_id)
    input2 = server.next_event(c_command.pipeline_id)
    input3 = server.next_event(c_command.pipeline_id)
    with pytest.raises(RunspacePoolWantRead):
        server.next_event(c_command.pipeline_id)
        
    assert isinstance(input1, PipelineInputEvent)
    assert isinstance(input1.ps_object, PSString)
    assert input1.ps_object == 'input 1'
    assert isinstance(input2, PipelineInputEvent)
    assert isinstance(input2.ps_object, PSString)
    assert input2.ps_object == 'input 2'
    assert isinstance(input3, PipelineInputEvent)
    assert isinstance(input3.ps_object, PSInt)
    assert input3.ps_object == 3

    c_pipeline.send_end()
    server.receive_data(client.data_to_send())
    end_of_input = server.next_event(c_command.pipeline_id)
    assert isinstance(end_of_input, EndOfPipelineInputEvent)

    s_pipeline.write_output('output')
    s_pipeline.write_debug('debug')
    s_pipeline.write_error(NETException('error'))
    s_pipeline.write_verbose('verbose')
    s_pipeline.write_warning('warning')
    s_pipeline.write_information('information', 'source')
    s_pipeline.write_progress('activity', 1, 'description')
    s_pipeline.close()
    client.receive_data(server.data_to_send())
    
    output_event = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(output_event, PipelineOutputEvent)
    assert isinstance(output_event.ps_object, PSString)
    assert output_event.ps_object == 'output'
    
    debug_event = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(debug_event, DebugRecordEvent)
    assert isinstance(debug_event.ps_object, InformationalRecord)
    assert debug_event.ps_object.InvocationInfo is None
    assert debug_event.ps_object.Message == 'debug'
    assert debug_event.ps_object.PipelineIterationInfo is None
    
    error_event = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(error_event, ErrorRecordEvent)
    assert isinstance(error_event.ps_object, ErrorRecord)
    assert str(error_event.ps_object) == 'error'
    assert isinstance(error_event.ps_object.Exception, NETException)
    assert error_event.ps_object.Exception.Message == 'error'
    assert isinstance(error_event.ps_object.CategoryInfo, ErrorCategoryInfo)
    assert str(error_event.ps_object.CategoryInfo), 'NotSpecified (:) [], '
    assert error_event.ps_object.CategoryInfo.Category == ErrorCategory.NotSpecified
    assert error_event.ps_object.CategoryInfo.Reason is None
    assert error_event.ps_object.CategoryInfo.TargetName is None
    assert error_event.ps_object.CategoryInfo.TargetType is None
    assert error_event.ps_object.ErrorDetails is None
    assert error_event.ps_object.InvocationInfo is None
    assert error_event.ps_object.PipelineIterationInfo is None
    assert error_event.ps_object.ScriptStackTrace is None
    assert error_event.ps_object.TargetObject is None
    
    verbose_event = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(verbose_event, VerboseRecordEvent)
    assert isinstance(verbose_event.ps_object, InformationalRecord)
    assert verbose_event.ps_object.InvocationInfo is None
    assert verbose_event.ps_object.Message == 'verbose'
    assert verbose_event.ps_object.PipelineIterationInfo is None
    
    warning_event = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(warning_event, WarningRecordEvent)
    assert isinstance(warning_event.ps_object, InformationalRecord)
    assert warning_event.ps_object.InvocationInfo is None
    assert warning_event.ps_object.Message == 'warning'
    assert warning_event.ps_object.PipelineIterationInfo is None
    
    info_event = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(info_event, InformationRecordEvent)
    assert isinstance(info_event.ps_object, InformationRecord)
    assert info_event.ps_object.Computer is not None
    assert info_event.ps_object.ManagedThreadId == 0
    assert info_event.ps_object.MessageData == 'information'
    assert info_event.ps_object.NativeThreadId > 0
    assert info_event.ps_object.ProcessId > 0
    assert info_event.ps_object.Source == 'source'
    assert info_event.ps_object.Tags == []
    assert info_event.ps_object.TimeGenerated is not None
    assert info_event.ps_object.User is not None
    
    progress_event = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(progress_event, ProgressRecordEvent)
    assert progress_event.ps_object.Activity == 'activity'
    assert progress_event.ps_object.ActivityId == 1
    assert progress_event.ps_object.CurrentOperation is None
    assert progress_event.ps_object.ParentActivityId == -1
    assert progress_event.ps_object.PercentComplete == -1
    assert progress_event.ps_object.SecondsRemaining == -1
    assert progress_event.ps_object.StatusDescription == 'description'
    assert progress_event.ps_object.Type == ProgressRecordType.Processing
    
    state_event = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(state_event, PipelineStateEvent)
    assert state_event.state == PSInvocationState.Completed
    
    with pytest.raises(RunspacePoolWantRead):
        client.next_event(c_pipeline.pipeline_id)


def test_pipeline_stop():
    client, server = get_runspace_pair()

    c_pipeline = ClientPowerShell(client, no_input=False)
    assert c_pipeline.state == PSInvocationState.NotStarted

    c_pipeline.add_script('script')
    c_pipeline.invoke()
    assert c_pipeline.state == PSInvocationState.Running

    c_command = client.data_to_send()
    server.receive_data(c_command)
    create_pipeline = server.next_event(c_command.pipeline_id)
    s_pipeline = create_pipeline.pipeline
    s_pipeline.state = PSInvocationState.Running

    s_pipeline.stop()
    assert s_pipeline.state == PSInvocationState.Stopped
    assert server.pipeline_table == {}
    
    client.receive_data(server.data_to_send())
    state = client.next_event(c_pipeline.pipeline_id)
    with pytest.raises(RunspacePoolWantRead):
        client.next_event(c_pipeline.pipeline_id)
        
    assert isinstance(state, PipelineStateEvent)
    assert isinstance(state.reason, ErrorRecord)
    assert state.state == PSInvocationState.Stopped
    assert str(state.reason) == 'The pipeline has been stopped.'
    assert str(state.reason.CategoryInfo) == 'OperationStopped (:) [], PipelineStoppedException'
    assert state.reason.CategoryInfo.Category == ErrorCategory.OperationStopped
    assert state.reason.CategoryInfo.Reason == 'PipelineStoppedException'
    assert state.reason.Exception.Message == 'The pipeline has been stopped.'
    assert state.reason.Exception.HResult == -2146233087
    assert state.reason.FullyQualifiedErrorId == 'PipelineStopped'
    assert state.reason.InvocationInfo is None
    assert state.reason.PipelineIterationInfo is None
    assert state.reason.ScriptStackTrace is None
    assert state.reason.TargetObject is None
    assert c_pipeline.state == PSInvocationState.Stopped
    assert client.pipeline_table == {}


def test_exchange_key_client():
    client, server = get_runspace_pair()

    client.exchange_key()
    server.receive_data(client.data_to_send())
    public_key = server.next_event()
    assert isinstance(public_key, PublicKeyEvent)
    
    client.receive_data(server.data_to_send())
    enc_key = client.next_event()
    assert isinstance(enc_key, EncryptedSessionKeyEvent)
    
    c_pipeline = ClientPowerShell(client)
    c_pipeline.add_script('command')
    c_pipeline.add_argument(PSSecureString('my secret'))
    c_pipeline.invoke()
    c_pipeline_data = client.data_to_send()
    assert b'my_secret' not in c_pipeline_data.data
    
    server.receive_data(c_pipeline_data)
    create_pipeline = server.next_event(c_pipeline.pipeline_id)
    assert isinstance(create_pipeline, CreatePipelineEvent)
    
    s_pipeline = create_pipeline.pipeline
    assert len(s_pipeline.commands) == 1
    assert s_pipeline.commands[0].command_text == 'command'
    assert s_pipeline.commands[0].parameters == [(None, 'my secret')]
    assert isinstance(s_pipeline.commands[0].parameters[0][1], PSSecureString)

    s_pipeline.state = PSInvocationState.Running
    s_pipeline.write_output(PSSecureString('secret output'))
    s_pipeline.close()
    s_output = server.data_to_send()
    assert s_pipeline.state == PSInvocationState.Completed
    assert server.pipeline_table == {}
    assert b'secret output' not in s_output
    
    client.receive_data(s_output)
    out = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(out, PipelineOutputEvent)
    assert isinstance(out.ps_object, PSSecureString)
    assert out.ps_object == 'secret output'
    
    state = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(state, PipelineStateEvent)
    assert state.state == PSInvocationState.Completed
    
    assert c_pipeline.state == PSInvocationState.Completed
    assert client.pipeline_table == {}


def test_exchange_key_request():
    client, server = get_runspace_pair()

    c_pipeline = ClientPowerShell(client)
    c_pipeline.add_script('command')
    c_pipeline.invoke()
    server.receive_data(client.data_to_send())
    s_pipeline = server.next_event(c_pipeline.pipeline_id).pipeline
    s_pipeline.state = PSInvocationState.Running
    
    with pytest.raises(MissingCipherError):
        s_pipeline.write_output(PSSecureString('secret'))

    server.request_key()
    client.receive_data(server.data_to_send())
    pub_key_req = client.next_event()
    assert isinstance(pub_key_req, PublicKeyRequestEvent)

    with pytest.raises(MissingCipherError):
        s_pipeline.write_output(PSSecureString('secret'))

    server.receive_data(client.data_to_send())
    pub_key = server.next_event()
    assert isinstance(pub_key, PublicKeyEvent)
    
    s_pipeline.write_output(PSSecureString('secret'))
    s_pipeline.close()
    assert s_pipeline.state == PSInvocationState.Completed
    assert server.pipeline_table == {}

    client.receive_data(server.data_to_send())
    enc_key = client.next_event()
    assert isinstance(enc_key, EncryptedSessionKeyEvent)

    b_data = server.data_to_send()
    client.receive_data(b_data)
    assert b'secret' not in b_data
    
    out = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(out, PipelineOutputEvent)
    assert isinstance(out.ps_object, PSSecureString)
    assert out.ps_object == 'secret'
    
    state = client.next_event(c_pipeline.pipeline_id)
    assert isinstance(state, PipelineStateEvent)
    assert state.state == PSInvocationState.Completed
    assert c_pipeline.state == PSInvocationState.Completed
    assert client.pipeline_table == {}
