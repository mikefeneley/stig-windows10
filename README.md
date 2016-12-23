# stig_windows10

<b>Update 11/13/2016:</b>

STIG-Windows10 was originally intended to be a vulnerability checker that checked windows configuration against the recommendations of the STIG guides provided by the DISA. The STIG-Apache used Python implementations of each individual STIG guide to check against the STIG requirements.

According to the NISA, the best way to implement a SCAP, (Security Content Automation Protocol), like STIG-Windows10 is to use OVAL, (Open Vulnerability and Assessment Language) repository to check the vulnerabilities provided by an XCCDF, (Extensible Configuration Checklist Description Format) and report the misconfigurations back the user.

Because the approach used to start this project is outdated and the correct approach is already implemented here: https://github.com/OpenSCAP, I am no longer going to continue regular work on this project. I may continue to write new methods in my free time in order to learn about STIG requirements, but it is no longer a personal priority.

<b>Update 11/26/2016:</b>

Initially this tool was originally intended to just check and report misconfiguations back to the user. However, adding the option to change or add configurations to make the system STIG compliant might help this tool stand out from many of the other STIG tools avaliable.

I am still going to work on extending the number of findings that are supported by the STIG Kit, but I also intend to add configuration change functitonality to the program.

<b>#################################################################</b>

<b>Introduction</b>

This program checks a subset of the configuration requirements of the DISA Windows 10 STIG. If any of the rules are violated, information about the violated rule is written to a configuration file for user review.


The subset of rules checked with their corresponding finding id in case of a violation is listed below.


Rule, Finding_ID

SV-78287r1_rule, V-63797

SV-78141r1_rule, V-63651

SV-77815r1_rule,  V-63325

SV-78157r1_rule, V-63667

SV-78249r1_rule, V-63759

SV-78163r1_rule, V-63673

SV-78161r1_rule, V-63671

SV-78235r1_rule, V-63745

SV-83445r1_rule, V-68849

SV-78299r1_rule, V-63809

SV-78291r1_rule, V-63801

SV-77837r1_rule, V-63347

SV-78239r1_rule, V-63749

SV-77825r1_rule, V-63335

SV-77901r2_rule, V-63411

SV-77881r3_rule,  V-63391

SV-78201r1_rule, V-63711

SV-78203r1_rule, V-63713

SV-78207r2_rule, V-63717

SV-78209r1_rule, V-63719

SV-78145r1_rule, V-63655

SV-78147r1_rule, V-63657

SV-78009r1_rule, V-63519

SV-77811r1_rule, V-63321

SV-83411r1_rule, V-68819

SV-78019r1_rule, V-63529

SV-78155r1_rule, V-63665

SV-78019r1_rule, V-63529

SV-78159r1_rule, V-63669

SV-77949r1_rule, V-63461

SV-78197r1_rule, V-63707

SV-78195r1_rule, V-63705

SV-78193r1_rule, V-63703

SV-78191r1_rule, V-63701

SV-78041r2_rule, V-63551

SV-78045r1_rule, V-63555

SV-78325r1_rule, V-63835

SV-78049r1_rule, V-63559

SV-77987r1_rule, V-63497

SV-78167r1_rule, V-63677

SV-77865r1_rule, V-63375

SV-77865r1_rule, V-63841

SV-78033r1_rule, V-63543

SV-78035r1_rule, V-63545

SV-78037r1_rule, V-63547

SV-78039r1_rule, V-63549

SV-77859r1_rule, V-63369

SV-78175r1_rule, V-63685

SV-78173r1_rule, V-63683

SV-78251r1_rule, V-63761

SV-78253r1_rule, V-63763

SV-78255r1_rule, V-63765

SV-78099r1_rule, V-63609

SV-78257r1_rule, V-63767

SV-83413r1_rule, V-68821

SV-78047r1_rule, V-63557

SV-78065r1_rule, V-63575

SV-78061r1_rule, V-63571

SV-78211r1_rule, V-63721

SV-78241r1_rule, V-63751

SV-78243r1_rule,  V-63753

SV-78087r1_rule, V-63597

SV-78105r1_rule, V-63615

SV-78107r1_rule, V-63617

SV-78081r1_rule, V-63591

SV-77915r2_rule, V-63425

SV-78319r1_rule, V-63829

SV-78017r1_rule, V-63527

SV-78317r1_rule, V-63827

SV-78315r1_rule, V-63825

SV-78285r1_rule, V-63795

SV-78213r1_rule, V-63723

SV-78015r1_rule, V-63525

SV-78121r1_rule, V-63631

SV-78051r1_rule, V-63561

SV-78013r1_rule, V-63523

SV-78233r1_rule, V-63743

SV-78169r1_rule, V-63679

SV-77995r1_rule, V-63505

SV-78189r1_rule, V-63699

SV-78075r1_rule, V-63585

SV-78119r1_rule, V-63629

SV-78231r1_rule, V-63741

SV-78327r1_rule, V-63837

SV-78321r1_rule, V-63831

SV-78055r1_rule, V-63565

SV-78245r1_rule, V-63755

SV-78029r1_rule, V-63539

SV-78059r1_rule, V-63569

SV-78227r1_rule, V-63737

SV-78225r1_rule, V-63735

SV-78223r1_rule, V-63733

SV-78221r1_rule, V-63731

SV-78129r1_rule, V-63639

SV-78127r1_rule, V-63637

SV-78123r1_rule, V-63633

SV-77923r2_rule, V-63433

SV-78215r1_rule, V-63725

SV-78125r1_rule, V-63635

SV-78293r1_rule, V-63803

SV-78295r1_rule, V-63805

SV-78297r1_rule, V-63807

SV-77831r1_rule, V-63341

SV-83409r1_rule, V-68817

SV-78307r1_rule, V-63817

SV-78139r1_rule, V-63649

SV-78303r1_rule, V-63813

SV-78301r1_rule, V-63811

SV-78133r1_rule, V-63643

SV-78131r1_rule, V-63641

SV-78137r1_rule, V-63647

SV-78219r1_rule, V-63729

SV-78135r1_rule, V-63645

SV-78309r1_rule, V-63819

SV-78447r1_rule, V-63957

SV-78113r1_rule, V-63623

SV-77823r1_rule, V-63333

SV-77829r1_rule, V-63339

SV-78149r1_rule, V-63659

SV-78205r1_rule, V-63715

SV-78143r1_rule,  V-63653

SV-78151r1_rule, V-63661

SV-78153r1_rule, V-63663

SV-78177r1_rule, V-63687

SV-78217r1_rule, V-63727

SV-78181r1_rule, V-63691

SV-78183r1_rule,  V-63693

SV-78053r1_rule, V-63563

SV-78057r1_rule, V-63567

SV-78329r1_rule, V-63839

SV-80171r1_rule, V-65681

<b>Using the Program</b>

The program can be run using the command line. Navigate to the src folder after downloading and execute program with the following command:

<i>python windows_auditor.py</i>

<br>
<br>
<b>Contact:</b>

Michael Feneley: mfeneley(at)vt.edu

