# Task-owned fixed queries followed by ordinary NPC movement.
use Time::HiRes qw(time);
my $finished = 0;
my $done = 0;
my $ticks = 0;
my $stable = 0;
sub EVENT_SPAWN { quest::settimer("server_collision", 1); }
sub EVENT_TIMER {
    return unless $timer eq "server_collision";
    if (-e "/runtime/stop-map-validation") {
        quest::stoptimer("server_collision");
        quest::debug("MAP_SERVER_PROBE_STOPPED");
        return;
    }
    return if $done;
    if ($finished) {
        ++$ticks;
        my ($x,$y,$z)=($npc->GetX(),$npc->GetY(),$npc->GetZ());
        my $g=$npc->FindGroundZ($x,$y,0);
        quest::debug("SERVER_COLLISION_POSE tick=$ticks xyz=$x,$y,$z ground=$g moving=".($npc->IsMoving()?1:0));
        if (abs($x-426.197)<0.5 && abs($y+560.964)<0.5 && !$npc->IsMoving()) { ++$stable; } else { $stable=0; }
        if ($stable>=3) { quest::debug("SERVER_COLLISION_ROUTE_DONE"); $done=1; }
        return;
    }
    $npc->GMMove(313.068,-560.554,-155.671,0,0);
    my ($sx,$sy,$sz,$size)=($npc->GetX(),$npc->GetY(),$npc->GetZ(),$npc->GetSize());
    # Offset zero plus FindBestZHeightAdjust=1 searches below the overhead roof.
    # These three floor samples are NOT a qualified height-transition route.
    for my $t (["start",313.068,-560.554,-155.671], ["clear",292.724,-560.235,-156.248], ["blocked",426.197,-560.964,-116.248]) {
        my ($id,$x,$y,$z)=@$t;
        my $ground=$npc->FindGroundZ($x,$y,0);
        my $los=$npc->CheckLoSToLoc($x,$y,$z,6) ? 1 : 0;
        my $eye=unpack("f",pack("f",$sz+unpack("f",pack("f",$size/2*unpack("f",pack("f",0.9))))));
        my $target_eye=unpack("f",pack("f",unpack("f",pack("f",$z))+1.5));
        my $adjusted=unpack("f",pack("f",$sz+1));
        quest::debug("SERVER_COLLISION_QUERY id=$id time=".time()." npc=".$npc->GetNPCTypeID()." entity=".$npc->GetID()." from=$sx,$sy,$sz size=$size origin=$x,$y,$sz adjusted=$x,$y,".$adjusted." eyes=$sx,$sy,$eye to=$x,$y,$z target_size=6 target_eyes=$x,$y,$target_eye ground=$ground los=$los");
    }
    quest::debug("SERVER_COLLISION_QUERIES_DONE");
    # Initial placement only. Subsequent displacement is native NPC MoveTo.
    $npc->StopNavigation();
    $npc->GMMove(313.068,-560.554,-155.671,0,0);
    for my $t (["route_start",313.068,-560.554,-155.671], ["transition",340.242,-561.633,-142.084], ["destination",426.197,-560.964,-116.248]) {
        my ($id,$x,$y,$z)=@$t;
        my $g=$npc->FindGroundZ($x,$y,$z-$npc->GetZ());
        quest::debug("SERVER_COLLISION_FLOOR id=$id xyz=$x,$y,$z ground=$g");
    }
    quest::debug("SERVER_COLLISION_REQUEST caller=Perl_NPC_MoveTo to=426.197,-560.964,-116.248");
    $npc->MoveTo(426.197,-560.964,-116.248,0,1);
    $finished=1;
}
