// src/components/RuleGroupsPanel.jsx

import React, { useMemo, useState } from 'react';
import { useRule } from '../context/RuleContext';
import { useDroppable } from '@dnd-kit/core';
import { Download, Edit2, Trash2, Eye, EyeOff, ArrowUp, ArrowDown, X } from 'lucide-react';

const GroupCard = ({ group }) => {
    const { isOver, setNodeRef, over } = useDroppable({ id: `group-drop-${group.id}` });
    const { getGroupRules, renameGroup, deleteGroup, exportGroup, reorderGroup, removeRuleFromGroup } = useRule();
    const [open, setOpen] = useState(true);
    const rules = useMemo(() => getGroupRules(group.id), [getGroupRules, group.id]);
    return (
        <div ref={setNodeRef} className={`group-card ${isOver ? 'drop-highlight' : ''}`} style={{ minHeight: isOver ? 80 : undefined }}>
            <div className="group-card-header">
                <div className="group-card-title">
                    <strong>{group.name}</strong>
                    <span className="group-meta">{rules.length} kural • {new Date(group.createdAt).toLocaleDateString()}</span>
                </div>
                <div className="group-card-actions">
                    <button title="Export" onClick={() => exportGroup(group.id)}><Download size={16} /></button>
                    <button title="Yeniden Adlandır" onClick={() => { const name = prompt('Grup adı', group.name); if (name) renameGroup(group.id, name); }}><Edit2 size={16} /></button>
                    <button title="Sil" onClick={() => { if (window.confirm('Grup silinsin mi?')) deleteGroup(group.id); }}><Trash2 size={16} /></button>
                    <button title={open ? 'Gizle' : 'Göster'} onClick={() => setOpen(v => !v)}>{open ? <EyeOff size={16} /> : <Eye size={16} />}</button>
                </div>
            </div>
            {isOver && <div className="drop-hint">Bu gruba kural(lar) eklenecek</div>}
            {open && (
                <div className="group-rules-list">
                    {rules.length === 0 ? <div className="panel-empty">Bu grupta kural yok.</div> : (
                        rules.map((r, idx) => (
                            <div key={r.id} className="group-rule-item">
                                <pre className="group-rule-text">{r.ruleString}</pre>
                                <div className="group-rule-actions">
                                    <button title="Yukarı" onClick={() => {
                                        if (idx === 0) return; const order = rules.map(x => x.id);
                                        const tmp = order[idx - 1]; order[idx - 1] = order[idx]; order[idx] = tmp;
                                        reorderGroup(group.id, order);
                                    }}><ArrowUp size={14}/></button>
                                    <button title="Aşağı" onClick={() => {
                                        if (idx === rules.length - 1) return; const order = rules.map(x => x.id);
                                        const tmp = order[idx + 1]; order[idx + 1] = order[idx]; order[idx] = tmp;
                                        reorderGroup(group.id, order);
                                    }}><ArrowDown size={14}/></button>
                                    <button className="group-rule-remove" title="Gruptan Kaldır" onClick={() => removeRuleFromGroup(group.id, r.id)}><X size={14}/></button>
                                </div>
                            </div>
                        ))
                    )}
                </div>
            )}
        </div>
    );
};

const RuleGroupsPanel = () => {
    const { ruleGroups, createGroup } = useRule();
    const [filter, setFilter] = useState('');
    const filtered = useMemo(() => {
        const q = filter.trim().toLowerCase();
        return q ? ruleGroups.filter(g => g.name.toLowerCase().includes(q)) : ruleGroups;
    }, [ruleGroups, filter]);

    return (
        <div className="groups-panel">
            <div className="panel-header-row">
                <h3>Gruplar</h3>
                <div className="panel-actions">
                    <input className="panel-search" placeholder="Ara..." value={filter} onChange={(e) => setFilter(e.target.value)} />
                    <button onClick={() => { const name = prompt('Yeni grup adı:'); if (name && name.trim()) createGroup(name.trim()); }}>+ Yeni Grup</button>
                </div>
            </div>
            <div className="groups-list">
                {filtered.length === 0 ? (
                    <div className="panel-empty">Henüz grup yok.</div>
                ) : (
                    filtered.map(g => <GroupCard key={g.id} group={g} />)
                )}
            </div>
        </div>
    );
};

export default RuleGroupsPanel;


