// src/components/Workbench.js

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useRule } from '../context/RuleContext';
import HeaderEditor from './HeaderEditor';
import FinalizedRule from './FinalizedRule';
import { toast } from 'react-toastify';
import InfoPanel from './InfoPanel';
import TopMenuBar from './TopMenuBar';
import ValidationPanel from './ValidationPanel';
import { DndContext, PointerSensor, KeyboardSensor, useSensor, useSensors, DragOverlay } from '@dnd-kit/core';
import { restrictToVerticalAxis } from '@dnd-kit/modifiers';
import { SortableContext, arrayMove, verticalListSortingStrategy, useSortable } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { optionsDictionary } from '../data/optionsDictionary';
import { FileUp, FileDown, CheckSquare, Square, Save, X, BookmarkPlus, TestTube2, Trash2 } from 'lucide-react';
import { generateRuleString } from '../utils/ruleGenerator';
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';

const Workbench = () => {

    const {
        ruleSessions,
        editingSourceId,
        isRulesListVisible,
        isInfoPanelVisible,
        appendImportedRules,
        selectedRuleIds,
        toggleRuleSelected,
        selectAllFinalized,
        clearSelection,
        deleteRulesByIds,
        updateRuleOptions,
        theme,
        finalizeRule,
        cancelEditing,
        saveUserTemplate,
        setRuleToTest,
        setInfoPanelTab,
        setInfoPanelVisibility,
        createGroup,
        addRulesToGroup,
        reorderRules,
        infoPanelTab,
    } = useRule();

    const activeSession = ruleSessions.find(session => session.status === 'editing');
    const finalizedSessions = useMemo(() => ruleSessions.filter(session => session.status === 'finalized'), [ruleSessions]);
    const fileInputRef = useRef(null);
    const rulesScrollRef = useRef(null);
    const [toolbarOpacity, setToolbarOpacity] = useState(0.9);
    const finalizedRuleIds = finalizedSessions.map(s => s.id);
    const allSelected = selectedRuleIds.length > 0 && selectedRuleIds.length === finalizedRuleIds.length;

    const prevProtocolRef = useRef();
    useEffect(() => {
        if (!activeSession) return;
        const currentProtocol = activeSession.headerData.Protocol;
        if (prevProtocolRef.current && currentProtocol !== prevProtocolRef.current) {
            const originalOptions = activeSession.ruleOptions;
            const cleanedOptions = originalOptions.filter(option => {
                const optionInfo = optionsDictionary[option.keyword];
                if (!optionInfo?.dependsOnProtocol) return true;
                return optionInfo.dependsOnProtocol === currentProtocol.toLowerCase();
            });
            const removedCount = originalOptions.length - cleanedOptions.length;
            if (removedCount > 0) {
                updateRuleOptions(activeSession.id, cleanedOptions);
                toast.warn(`${removedCount} adet seçenek, yeni protokolle uyumsuz olduğu için kaldırıldı.`);
            }
        }
        prevProtocolRef.current = currentProtocol;
    }, [activeSession?.headerData.Protocol, activeSession?.id, activeSession?.ruleOptions, updateRuleOptions]);

    const handleExport = () => {
        if (selectedRuleIds.length === 0) {
            toast.warn('Lütfen önce en az bir kural seçin.');
            return;
        }
        const rulesToExport = finalizedSessions.filter(session => selectedRuleIds.includes(session.id));
        if (rulesToExport.length === 0) {
            toast.warn('Seçili kurallar bulunamadı.');
            return;
        }
        const rulesString = rulesToExport.map(session => session.ruleString).join('\n\n');
        const blob = new Blob([rulesString], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'custom.rules';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    const handleActiveRuleTest = () => {
        if (!activeSession) return;
        const currentRuleString = generateRuleString(activeSession.headerData, activeSession.ruleOptions);
        if (!currentRuleString || !currentRuleString.includes('sid:')) {
            toast.warn('Test etmek için lütfen önce geçerli bir kural oluşturun.');
            return;
        }
        setRuleToTest(currentRuleString);
        setInfoPanelTab('test_lab');
        toast.info('Aktif kural, test için laboratuvara gönderildi.');
    };

    const handleImportClick = () => { fileInputRef.current?.click(); };

    // DnD sensors
    const sensors = useSensors(
        useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
        useSensor(KeyboardSensor)
    );

    const [activeDragId, setActiveDragId] = useState(null);
    const activeDragSession = useMemo(() => {
        if (!activeDragId) return null;
        return ruleSessions.find(s => s.id === activeDragId) || null;
    }, [activeDragId, ruleSessions]);

    const RuleDragPreview = ({ session }) => {
        if (!session) return null;
        return (
            <div className="drag-preview-card">
                <div className="drag-preview-header">Kural Önizleme</div>
                <pre className="drag-preview-body">{session.ruleString}</pre>
            </div>
        );
    };

    const onDragStart = (event) => {
        setActiveDragId(event?.active?.id || null);
    };

    const onDragEnd = (event) => {
        const { active, over } = event || {};
        setActiveDragId(null);
        if (!active || !over) return;
        const overId = typeof over.id === 'string' ? over.id : '';
        // Liste içi sıralama
        const ids = finalizedSessions.slice().reverse().map(s => s.id);
        if (ids.includes(active.id) && ids.includes(over.id)) {
            const oldIndex = ids.indexOf(active.id);
            const newIndex = ids.indexOf(over.id);
            const displayOrder = arrayMove(ids, oldIndex, newIndex);
            // Ana liste doğal sırası, tersine çevrilmiş halidir
            const naturalOrder = displayOrder.slice().reverse();
            reorderRules(naturalOrder);
        }
    };

    // Scroll kilidi: sürükleme sırasında tekerlek/scroll engelle
    useEffect(() => {
        const el = rulesScrollRef.current;
        if (!activeDragId || !el) return;
        const prevOverflowX = el.style.overflowX;
        el.classList.add('drag-x-lock');
        el.style.overflowX = 'hidden';

        // Kilitle: scrollLeft sabit tut
        const lockLeft = () => { if (el.scrollLeft !== 0) el.scrollLeft = 0; };
        const onScroll = () => lockLeft();
        el.addEventListener('scroll', onScroll, { passive: true });
        lockLeft();

        const onWheel = (e) => {
            if (Math.abs(e.deltaX) > 0) {
                e.preventDefault();
                e.stopPropagation();
                // Yalnızca dikey kaydır
                if (Math.abs(e.deltaY) > 0) el.scrollTop += e.deltaY;
            }
        };
        let lastX = 0; let lastY = 0;
        const onTouchStart = (e) => {
            const t = e.touches && e.touches[0];
            if (t) { lastX = t.clientX; lastY = t.clientY; }
        };
        const onTouchMove = (e) => {
            const t = e.touches && e.touches[0];
            if (!t) return;
            const dx = t.clientX - lastX;
            const dy = t.clientY - lastY;
            lastX = t.clientX; lastY = t.clientY;
            if (Math.abs(dx) > Math.abs(dy)) {
                // Yatay hareket: default'u engelle, dikeye uygula
                e.preventDefault();
                e.stopPropagation();
                el.scrollTop -= dy;
            }
        };
        el.addEventListener('wheel', onWheel, { passive: false });
        el.addEventListener('touchstart', onTouchStart, { passive: true });
        el.addEventListener('touchmove', onTouchMove, { passive: false });

        // Kaçak yatay wheel'i de engelle (ancak dikeyi koru)
        const onWinWheel = (e) => {
            if (Math.abs(e.deltaX) > 0) {
                e.preventDefault();
            }
        };
        window.addEventListener('wheel', onWinWheel, { passive: false });

        return () => {
            el.classList.remove('drag-x-lock');
            el.style.overflowX = prevOverflowX;
            el.removeEventListener('scroll', onScroll);
            el.removeEventListener('wheel', onWheel);
            el.removeEventListener('touchstart', onTouchStart);
            el.removeEventListener('touchmove', onTouchMove);
            window.removeEventListener('wheel', onWinWheel);
        };
    }, [activeDragId]);

    const handleBulkDelete = () => {
        if (selectedRuleIds.length === 0) {
            toast.warn('Lütfen önce silmek için en az bir kural seçin.');
            return;
        }
        deleteRulesByIds(selectedRuleIds);
    };

    const handleImportFile = async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        try {
            const form = new FormData();
            form.append('file', file);
            const res = await fetch('/rules/parse', { method: 'POST', body: form });
            if (!res.ok) throw new Error('Sunucu hatası');
            const data = await res.json();
            if (!data || !Array.isArray(data.rules)) throw new Error('Geçersiz yanıt');
            appendImportedRules(data.rules);
        } catch (err) {
            toast.error('İçe aktarma başarısız: ' + (err?.message || 'Bilinmeyen hata'));
        } finally {
            if (fileInputRef.current) fileInputRef.current.value = '';
        }
    };

    const [isGroupingOpen, setIsGroupingOpen] = useState(false);
    const [groupName, setGroupName] = useState('');

    const handleOpenGrouping = () => {
        if (selectedRuleIds.length === 0) {
            toast.warn('Lütfen önce en az bir kural seçin.');
            return;
        }
        setIsGroupingOpen(true);
    };

    const handleConfirmGrouping = () => {
        if (selectedRuleIds.length === 0) {
            toast.warn('Lütfen önce en az bir kural seçin.');
            return;
        }
        const name = (groupName || '').trim();
        if (!name) { toast.warn('Lütfen grup adı girin.'); return; }
        const gid = createGroup(name);
        addRulesToGroup(gid, selectedRuleIds);
        setGroupName('');
        setIsGroupingOpen(false);
        toast.success('Seçili kurallar gruplandırıldı.');
    };

    return (
        <div className={`app-container`}>
            <TopMenuBar />
            <div className="app-layout-resizable">
                <DndContext sensors={sensors} onDragStart={onDragStart} onDragEnd={onDragEnd} modifiers={[restrictToVerticalAxis]}>
                <PanelGroup direction="horizontal" className="panels-root" style={{ height: '100%' }}>
                    <Panel defaultSize={65} minSize={45}>
                        <div className="main-content-area glass-effect">
                            <div className="active-editor-container">
                                {activeSession ? (
                                    <div className="active-editor-wrapper">
                                        <HeaderEditor key={activeSession.id} session={activeSession} />
                                    </div>
                                ) : (
                                    <p>Yeni kural oluşturuluyor...</p>
                                )}
                                <ValidationPanel />
                            </div>

                            <div className="global-action-bar">
                                <div className="toolbar-group-left">
                                    <button onClick={handleImportClick}><FileUp size={16}/> Import</button>
                                    <button onClick={handleExport}><FileDown size={16}/> Export</button>
                                    <div style={{ position: 'relative', display: 'inline-block' }}>
                                        <button onClick={handleOpenGrouping}>Gruplandır</button>
                                        {isGroupingOpen && (
                                            <div style={{ position: 'absolute', top: '110%', left: 0, zIndex: 2000, background: 'var(--bg-panel)', border: '1px solid var(--border-primary)', borderRadius: 8, padding: 8, display: 'flex', gap: 8, alignItems: 'center' }}>
                                                <input
                                                    type="text"
                                                    placeholder="Grup adı"
                                                    value={groupName}
                                                    onChange={(e) => setGroupName(e.target.value)}
                                                    style={{ background: 'var(--bg-input)', color: 'var(--text-primary)', border: '1px solid var(--border-primary)', borderRadius: 6, padding: '6px 8px' }}
                                                />
                                                <button onClick={handleConfirmGrouping}>Oluştur</button>
                                                <button onClick={() => setIsGroupingOpen(false)}>İptal</button>
                                            </div>
                                        )}
                                    </div>
                                    <button onClick={() => { allSelected ? clearSelection() : selectAllFinalized(); }}>
                                        {allSelected ? <CheckSquare size={16}/> : <Square size={16}/>} {allSelected ? 'Seçimi Bırak' : 'Tümünü Seç'}
                                    </button>
                                    <button onClick={handleBulkDelete}><Trash2 size={16}/> Sil</button>
                                </div>

                                <div className='action-bar-spacer'></div>

                                <div className="toolbar-group-right">
                                    <button onClick={() => activeSession && finalizeRule(activeSession.id)}><Save size={16}/> Kaydet</button>
                                    <button onClick={cancelEditing}><X size={16}/> İptal Et</button>
                                    <button onClick={saveUserTemplate}><BookmarkPlus size={16}/> Şablon Yap</button>
                                    <button onClick={handleActiveRuleTest}><TestTube2 size={16}/> Test Et</button>
                                </div>
                            </div>

                            {isRulesListVisible && (
                                <div className="finalized-rules-list">
                                    <input type="file" ref={fileInputRef} style={{ display: 'none' }} onChange={handleImportFile} accept=".rules,.txt" />
                                    <div
                                        className="rules-scroll-wrapper"
                                        ref={rulesScrollRef}
                                        onScroll={(e) => {
                                            const t = e.currentTarget.scrollTop || 0;
                                            const next = Math.max(0.2, 1 - t / 300);
                                            setToolbarOpacity(next);
                                        }}
                                    >
                                        <SortableContext items={finalizedSessions.slice().reverse().map(s => s.id)} strategy={verticalListSortingStrategy}>
                                            {finalizedSessions.slice().reverse().map(session => (
                                                <FinalizedRule
                                                    key={session.id}
                                                    session={session}
                                                    isBeingEdited={session.id === editingSourceId}
                                                    isSelected={selectedRuleIds.includes(session.id)}
                                                    onToggleSelected={() => toggleRuleSelected(session.id)}
                                                />
                                            ))}
                                        </SortableContext>
                                    </div>
                                </div>
                            )}
                        </div>
                    </Panel>

                    <PanelResizeHandle className="resize-handle" />

                    <Panel defaultSize={35} minSize={15} collapsible collapsedSize={0}
                        onCollapse={() => { if (isInfoPanelVisible) setInfoPanelVisibility(false); }}
                        onExpand={() => { if (!isInfoPanelVisible) setInfoPanelVisibility(true); }}
                    >
                        <div className="right-info-panel glass-effect">
                            <InfoPanel />
                        </div>
                    </Panel>
                </PanelGroup>
                <DragOverlay>
                    {activeDragId ? (
                        <div style={{ padding: 8, borderRadius: 9999, background: 'var(--bg-panel-solid)', border: '1px solid var(--border-primary)', boxShadow: '0 12px 28px rgba(0,0,0,0.35)', color: 'var(--text-primary)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 5H21" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/><path d="M3 5H3.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/><path d="M8 12H21" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/><path d="M3 12H3.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/><path d="M8 19H21" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/><path d="M3 19H3.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/></svg>
                            <span>{selectedRuleIds.includes(activeDragId) ? `${selectedRuleIds.length} kural` : 'Kural'}</span>
                        </div>
                    ) : null}
                </DragOverlay>
                </DndContext>
            </div>
        </div>

    );
};

export default Workbench;