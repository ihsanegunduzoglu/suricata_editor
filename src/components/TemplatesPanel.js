// src/components/TemplatesPanel.js

import React from 'react';
import { useRule } from '../context/RuleContext';
import { templatesData } from '../data/templatesData';
import { LayoutTemplate, Trash2, Bookmark } from 'lucide-react';

const TemplatesPanel = () => {
    // userTemplates ve deleteUserTemplate fonksiyonlarını context'ten al
    const { applyTemplate, userTemplates, deleteUserTemplate } = useRule();

    const handleTemplateClick = (template) => {
        const newRuleOptions = template.data.ruleOptions.map(opt => ({ ...opt, id: Math.random().toString(36).substr(2, 9) }));
        const templateDataWithNewIds = {
            ...template.data,
            ruleOptions: newRuleOptions
        };
        applyTemplate(templateDataWithNewIds);
    };

    return (
        <div className="templates-panel">
            <h3><LayoutTemplate size={20} /> Kural Şablonları</h3>
            <p className="panel-description">
                Yaygın senaryolar için bir şablona tıklayarak kural yazmaya hızlıca başlayın.
            </p>
            
            {/* HAZIR ŞABLONLAR BÖLÜMÜ */}
            <h4 className="template-section-header">Hazır Şablonlar</h4>
            <ul className="info-options-list">
                {templatesData.map(template => (
                    <li 
                        key={template.id} 
                        className="template-item"
                        onClick={() => handleTemplateClick(template)}
                        title="Bu şablonu editöre yükle"
                    >
                        <strong className="template-name">{template.name}</strong>
                        <span className="template-description">{template.description}</span>
                    </li>
                ))}
            </ul>

            {/* KULLANICI ŞABLONLARI BÖLÜMÜ */}
            <h4 className="template-section-header user-templates-header">
                <Bookmark size={16} /> Kaydedilmiş Şablonlarım
            </h4>
            <ul className="info-options-list">
                {userTemplates.length > 0 ? (
                    userTemplates.map(template => (
                        <li 
                            key={template.id} 
                            className="template-item user-template-item"
                            onClick={() => handleTemplateClick(template)}
                            title="Bu şablonu editöre yükle"
                        >
                            <div className="user-template-content">
                                <strong className="template-name">{template.name}</strong>
                                <span className="template-description">{template.description}</span>
                            </div>
                            <button 
                                className="delete-template-btn" 
                                onClick={(e) => {
                                    e.stopPropagation(); // li'nin tıklanmasını engelle
                                    deleteUserTemplate(template.id);
                                }}
                                title="Bu şablonu sil"
                            >
                                <Trash2 size={14} />
                            </button>
                        </li>
                    ))
                ) : (
                    <p className="no-user-templates">
                        Henüz hiç şablon kaydetmediniz. <br/>
                        Editörde bir kural hazırlayıp "Kaydet" ikonuna tıklayarak kendi şablonlarınızı oluşturabilirsiniz.
                    </p>
                )}
            </ul>
        </div>
    );
};

export default TemplatesPanel;