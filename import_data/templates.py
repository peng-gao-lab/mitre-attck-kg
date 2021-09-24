#! python3
# *_template functions definition

# Add entities templates
# Add string properties
def addStr(entity, ppt):
    p = entity.get(ppt, None)
    if p:
        return ', has ' + ppt + '"' + p + '"'
    else:
        return ''

# Add date properties
def addDate(entity, ppt):
    p = entity.get(ppt, None)
    if p:
        return ', has ' + ppt + str(p)[:23]
    else:
        return ''

# Add boolean
def addBool(entity, ppt):
    p = entity.get(ppt, None)
    if p:
        return ', has ' + ppt + str(p).lower()
    else:
        return ''

# Add List properties
def addList(entity, ppts):
    res = ''
    ppt = entity.get(ppts, None)
    if not ppt:
        return ''
    for p in ppt:
        res += ', has ' + ppts + '"' + p +'"'
    return res


'''
    "identity": [
        "type",
        "spec_version",
        "id",
        "created",
        "modified",
        "name",
        "identity_class",
        "revoked",
        "object_marking_refs",
        "x_mitre_domains",
        "x_mitre_version"
    ],
    type => types
'''
def identity_template(identity):
    temp = 'insert $identity isa identity, has id "' + identity["id"] + '"'
    temp += addStr(identity, "types")
    temp += addStr(identity, "name")
    temp += addStr(identity, "spec_version")
    temp += addDate(identity, "created")
    temp += addDate(identity, "modified")
    temp += addStr(identity, "x_mitre_version")
    temp += addList(identity, "x_mitre_domains")
    temp += addBool(identity, "revoked")
    temp += addStr(identity, "identity_class")
    temp += ';'
    return temp


'''
    "marking-definition": [
        "type",
        "spec_version",
        "id",
        "created_by_ref",
        "created",
        "definition_type",
        "definition",
        "x_mitre_domains"
    ]
    type => types
'''
def marking_definition_template(marking_definition):
    temp = 'insert $md isa marking-definition, has id "' + marking_definition["id"] + '""'
    temp += addStr(marking_definition, "types")
    temp += addStr(marking_definition, "spec_version")
    temp += addDate(marking_definition, "created")
    temp += addStr(marking_definition, "definition_type")
    temp += ', has definition "' + marking_definition["definition_type"] +
        marking_definition["definition"][marking_definition["definition_type"]] + '"'
    temp += addList(marking_definition, "x_mitre_domains")
    temp += ';'
    return temp

'''
    "attack-pattern": [
        "type",
        "spec_version",
        "id",
        "created_by_ref",
        "created",
        "modified",
        "name",
        "description",
        "kill_chain_phases",
        "revoked",
        "external_references",
        "object_marking_refs",
        "x_mitre_data_sources",
        "x_mitre_detection",
        "x_mitre_domains",
        "x_mitre_is_subtechnique",
        "x_mitre_modified_by_ref",
        "x_mitre_permissions_required",
        "x_mitre_platforms",
        "x_mitre_version",
        "x_mitre_contributors",
        "x_mitre_system_requirements",
        "x_mitre_defense_bypassed",
        "x_mitre_effective_permissions",
        "x_mitre_impact_type",
        "x_mitre_network_requirements",
        "x_mitre_remote_support",
        "x_mitre_deprecated"
    ],
    type => types
'''
def technique_template(technique):
    # Common properties
    temp = 'insert $tech isa attack-pattern, has id "' + technique["id"] + '"'
    temp += addStr(technique, "types")
    temp += addStr(technique, "name")
    temp += addStr(technique, "spec_version")
    temp += addDate(technique, "created")
    temp += addDate(technique, "modified")
    temp += addStr(technique, "x_mitre_version")
    temp += addList(technique, "x_mitre_domains")

    # Particular properties
    temp += addBool(technique, "revoked")
    temp += addStr(technique, "description")
    temp += addList(technique, "x_mitre_data_sources")
    temp += addStr(technique, "x_mitre_detection")
    temp += addBool(technique, "x_mitre_is_subtechnique")
    temp += addList(technique, "x_mitre_permissions_required")
    temp += addList(technique, "x_mitre_platforms")
    temp += addList(technique, "x_mitre_contributors")
    temp += addList(technique, "x_mitre_system_requirements")
    temp += addList(technique, "x_mitre_defense_bypassed")
    temp += addList(technique, "x_mitre_effective_permissions")
    temp += addList(technique, "x_mitre_impact_type")
    temp += addList(technique, "x_mitre_network_requirements")
    temp += addBool(technique, "x_mitre_remote_support")
    temp += addBool(technique, "x_mitre_deprecated")

    temp += ';'
    return temp

'''
    "malware": [
        "type",
        "spec_version",
        "id",
        "created_by_ref",
        "created",
        "modified",
        "name",
        "description",
        "is_family",
        "revoked",
        "external_references",
        "object_marking_refs",
        "x_mitre_aliases",
        "x_mitre_domains",
        "x_mitre_modified_by_ref",
        "x_mitre_platforms",
        "x_mitre_version",
        "x_mitre_contributors",
        "x_mitre_old_attack_id"
    ],
    "tool": [
        "type",
        "spec_version",
        "id",
        "created_by_ref",
        "created",
        "modified",
        "name",
        "description",
        "revoked",
        "external_references",
        "object_marking_refs",
        "x_mitre_aliases",
        "x_mitre_domains",
        "x_mitre_modified_by_ref",
        "x_mitre_platforms",
        "x_mitre_version",
        "x_mitre_contributors",
        "x_mitre_deprecated"
    ],
    type => types
'''
def software_template(software):
    # Common properties
    temp = 'insert $sw isa software, has id "' + software["id"] + '"'
    temp += addStr(software, "types")
    temp += addStr(software, "name")
    temp += addStr(software, "spec_version")
    temp += addDate(software, "created")
    temp += addDate(software, "modified")
    temp += addStr(software, "x_mitre_version")
    temp += addList(software, "x_mitre_domains")

    # Particular properties
    temp += addBool(software, "revoked")
    temp += addStr(software, "description")
    temp += addList(software, "x_mitre_platforms")
    temp += addList(software, "x_mitre_contributors")
    temp += addBool(software, "x_mitre_deprecated")
    temp += addList(software, "x_mitre_aliases")
    temp += addStr(software, "x_mitre_old_attack_id")

    temp += ';'
    return temp

'''
    "intrusion-set": [
        "type",
        "spec_version",
        "id",
        "created_by_ref",
        "created",
        "modified",
        "name",
        "description",
        "aliases",
        "revoked",
        "external_references",
        "object_marking_refs",
        "x_mitre_contributors",
        "x_mitre_domains",
        "x_mitre_modified_by_ref",
        "x_mitre_version",
        "x_mitre_deprecated"
    ],
    type => types
'''
def groups_template(groups):
    # Common properties
    temp = 'insert $sw isa groups, has id "' + groups["id"] + '"'
    temp += addStr(groups, "types")
    temp += addStr(groups, "name")
    temp += addStr(groups, "spec_version")
    temp += addDate(groups, "created")
    temp += addDate(groups, "modified")
    temp += addStr(groups, "x_mitre_version")
    temp += addList(groups, "x_mitre_domains")

    # Particular properties
    temp += addBool(groups, "revoked")
    temp += addStr(groups, "description")
    temp += addList(groups, "x_mitre_contributors")
    temp += addBool(groups, "x_mitre_deprecated")
    temp += addList(groups, "aliases")

    temp += ';'
    return temp


'''
    "course-of-action": [
        "type",
        "spec_version",
        "id",
        "created_by_ref",
        "created",
        "modified",
        "name",
        "description",
        "revoked",
        "external_references",
        "object_marking_refs",
        "x_mitre_deprecated",
        "x_mitre_domains",
        "x_mitre_modified_by_ref",
        "x_mitre_version",
        "x_mitre_old_attack_id"
    ],
    type => types
'''
def mitigation_template(mitigation):
    # Common properties
    temp = 'insert $sw isa mitigation, has id "' + mitigation["id"] + '"'
    temp += addStr(mitigation, "types")
    temp += addStr(mitigation, "name")
    temp += addStr(mitigation, "spec_version")
    temp += addDate(mitigation, "created")
    temp += addDate(mitigation, "modified")
    temp += addStr(mitigation, "x_mitre_version")
    temp += addList(mitigation, "x_mitre_domains")

    # Particular properties
    temp += addBool(mitigation, "revoked")
    temp += addBool(mitigation, "x_mitre_deprecated")
    temp += addStr(mitigation, "x_mitre_old_attack_id")

    temp += ';'
    return temp


'''
    "x-mitre-tactic": [
        "id",
        "created_by_ref",
        "name",
        "description",
        "external_references",
        "object_marking_refs",
        "x_mitre_shortname",
        "type",
        "modified",
        "created",
        "spec_version",
        "x_mitre_domains",
        "x_mitre_modified_by_ref",
        "x_mitre_version"
    ],
    type => types
'''
def tactic_template(tactic):
    # Common properties
    temp = 'insert $sw isa tactic, has id "' + tactic["id"] + '"'
    temp += addStr(tactic, "types")
    temp += addStr(tactic, "name")
    temp += addStr(tactic, "spec_version")
    temp += addDate(tactic, "created")
    temp += addDate(tactic, "modified")
    temp += addStr(tactic, "x_mitre_version")
    temp += addList(tactic, "x_mitre_domains")

    # Particular properties
    temp += addStr(tactic, "x_mitre_shortname")

    temp += ';'
    return temp


'''
    "x-mitre-matrix": [
        "id",
        "created_by_ref",
        "name",
        "description",
        "external_references",
        "object_marking_refs",
        "type",
        "tactic_refs",
        "modified",
        "created",
        "spec_version",
        "x_mitre_domains",
        "x_mitre_modified_by_ref",
        "x_mitre_version"
    ],
    type => types
'''
def matrix_template(tactic):
    # Common properties
    temp = 'insert $sw isa matrix, has id "' + matrix["id"] + '"'
    temp += addStr(matrix, "types")
    temp += addStr(matrix, "name")
    temp += addStr(matrix, "spec_version")
    temp += addDate(matrix, "created")
    temp += addDate(matrix, "modified")
    temp += addStr(matrix, "x_mitre_version")
    temp += addList(matrix, "x_mitre_domains")

    # Particular properties
    temp += addStr(matrix, "description")

    temp += ';'
    return temp


'''
    "external_references": [
        "source_name",
        "url",
        "external_id",
        "description"
    ]

external_references sub relation,
    relates owner,
    relates listed;
'''
def external_reference_template(external_reference):
    temp = 'insert $er isa external_reference'
    temp += addStr(external_reference, "external_id")
    temp += addStr(external_reference, "url")
    temp += addStr(external_reference, "er_description")
    temp += addStr(external_reference, "source_name")
    temp += ';'
    return temp


'''
    "kill_chain_phases": [
        "kill_chain_name",
        "phase_name"
    ],
'''
def kill_chain_phase_template(kill_chain_phase):
    temp = 'insert $kcp isa kill_chain_phase'
    temp += addStr(kill_chain_phase, "kill_chain_name")
    temp += addStr(kill_chain_phase, "phase_name")
    temp += ';'
    return temp



# Add references templates
'''
created_by_ref sub relation,
    relates created,
    relates ref;
'''
def created_by_ref_template(sid, ttype, tid):
    temp = 'match $source isa ' + ttype +', has id "' + sid + '";'
    temp += ' $target isa identity, has id "' + tid + '";'
    temp += " insert (created: $source, ref: $target) isa created_by_ref;"
    return temp


'''
object_marking_refs sub relation,
    relates marked,
    relates ref;
'''
def object_marking_ref(sid, ttype, tids):
    temp = 'match $source isa ' + ttype +', has id "' + sid + '";'
    for tid in tids:
        temp += ' $target isa marking-definition, has id "' + tid + '";'
        temp += " insert (marked: $source, ref: $target) isa object_marking_refs;"
    return temp


'''
x_mitre_modified_by_ref sub relation,
    relates modified,
    relates ref;
'''
def x_mitre_modified_by_ref(sid, ttype, tid):
    temp = 'match $source isa ' + ttype +', has id "' + sid + '";'
    temp += ' $target isa identity, has id "' + tid + '";'
    temp += " insert (modified: $source, ref: $target) isa x_mitre_modified_by_ref;"
    return temp


'''
tactic_refs sub relation,
    relates owner,
    relates listed;

fun(matrix["id"], tactic["id"])
'''
def tactic_refs_template(sid, tids):
    temp = 'match $matrix isa matrix, has id "' + sid + '";'
    for tid in tids:
        temp += '$tactic isa tactic, has id "' + tid + '";'
        temp += ' insert (owner: $matrix, listed: $tactic) isa tactic_refs;'
    return temp


'''
'''
